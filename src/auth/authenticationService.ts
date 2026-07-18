import type { Model } from 'mongoose';

import type { AuthenticatedSession, AuthenticationService } from '../contracts';
import {
    MAX_USER_SESSIONS,
    TOKEN_HASH_PATTERN,
    User,
    type UserDocument,
    type UserSession,
} from '../schemas/usersSchema';
import { generateRawToken, hashToken, RAW_TOKEN_PATTERN } from './token';

const DEFAULT_TOUCH_INTERVAL_MS = 15 * 60 * 1_000;
const MAX_SESSION_CREATION_ATTEMPTS = 10;

export interface AuthenticationServiceOptions {
    userModel?: Model<UserDocument>;
    sessionTouchIntervalMs?: number;
    now?: () => Date;
    tokenGenerator?: () => string;
}

function isDuplicateKeyError(error: unknown): boolean {
    return typeof error === 'object'
        && error !== null
        && 'code' in error
        && error.code === 11_000;
}

function sessionSort(): Record<keyof Pick<UserSession, 'lastUsedAt' | 'createdAt' | 'tokenHash'>, 1 | -1> {
    return { lastUsedAt: -1, createdAt: -1, tokenHash: 1 };
}

interface FoundSession extends AuthenticatedSession {
    lastUsedAt: Date | undefined;
}

class MongooseAuthenticationService implements AuthenticationService {
    constructor(
        private readonly userModel: Model<UserDocument>,
        private readonly sessionTouchIntervalMs: number,
        private readonly now: () => Date,
        private readonly tokenGenerator: () => string,
    ) {}

    async authenticate(rawAuthorization: string): Promise<AuthenticatedSession | null> {
        const found = await this.findSession(rawAuthorization);
        if (!found) return null;

        const { userId, tokenHash, lastUsedAt } = found;
        const now = this.now();
        const staleBefore = new Date(now.getTime() - this.sessionTouchIntervalMs);
        if (lastUsedAt && lastUsedAt < staleBefore) {
            await this.userModel.updateOne(
                {
                    userId,
                    sessions: {
                        $elemMatch: {
                            tokenHash,
                            lastUsedAt: { $lt: staleBefore },
                        },
                    },
                },
                { $set: { 'sessions.$.lastUsedAt': now } },
            );
        }

        return { userId, tokenHash };
    }

    async authenticateReadOnly(rawAuthorization: string): Promise<AuthenticatedSession | null> {
        const found = await this.findSession(rawAuthorization);
        return found ? { userId: found.userId, tokenHash: found.tokenHash } : null;
    }

    private async findSession(rawAuthorization: string): Promise<FoundSession | null> {
        const tokenHash = hashToken(rawAuthorization);
        const user = await this.userModel
            .findOne(
                { 'sessions.tokenHash': tokenHash },
                { _id: 0, userId: 1, sessions: { $elemMatch: { tokenHash } } },
            )
            .lean();

        if (!user) return null;
        return { userId: user.userId, tokenHash, lastUsedAt: user.sessions[0]?.lastUsedAt };
    }

    async createSession(userId: string): Promise<string> {
        for (let attempt = 0; attempt < MAX_SESSION_CREATION_ATTEMPTS; attempt += 1) {
            const rawToken = this.tokenGenerator();
            if (!RAW_TOKEN_PATTERN.test(rawToken)) {
                throw new Error('Token generator returned an invalid token');
            }

            const tokenHash = hashToken(rawToken);
            if (!TOKEN_HASH_PATTERN.test(tokenHash)) {
                throw new Error('Token hash generation failed');
            }

            const timestamp = this.now();
            const session: UserSession = {
                tokenHash,
                createdAt: timestamp,
                lastUsedAt: timestamp,
            };

            try {
                await this.userModel.updateOne(
                    { userId, 'sessions.tokenHash': { $ne: tokenHash } },
                    {
                        $setOnInsert: { userId },
                        $push: {
                            sessions: {
                                $each: [session],
                                $sort: sessionSort(),
                                $slice: MAX_USER_SESSIONS,
                            },
                        },
                    },
                    {
                        upsert: true,
                        runValidators: true,
                        setDefaultsOnInsert: false,
                    },
                );
                return rawToken;
            } catch (error) {
                if (!isDuplicateKeyError(error)) throw error;
            }
        }

        throw new Error('Unable to create a unique session');
    }

    async revokeAllSessions(userId: string): Promise<void> {
        await this.userModel.deleteOne({ userId });
    }
}

/** Create the service used by the v1 routes; injected model/clock hooks support focused tests. */
export function createAuthenticationService(
    options: AuthenticationServiceOptions = {},
): AuthenticationService {
    const sessionTouchIntervalMs = options.sessionTouchIntervalMs ?? DEFAULT_TOUCH_INTERVAL_MS;
    if (!Number.isSafeInteger(sessionTouchIntervalMs) || sessionTouchIntervalMs <= 0) {
        throw new Error('sessionTouchIntervalMs must be a positive integer');
    }

    return new MongooseAuthenticationService(
        options.userModel ?? User,
        sessionTouchIntervalMs,
        options.now ?? (() => new Date()),
        options.tokenGenerator ?? generateRawToken,
    );
}
