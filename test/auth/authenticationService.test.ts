import { describe, expect, test } from 'bun:test';
import type { Model } from 'mongoose';

import { createAuthenticationService, generateRawToken, hashToken } from '../../src/auth';
import { type UserDocument, type UserSession } from '../../src/schemas/usersSchema';

type UpdateCall = {
    filter: Record<string, unknown>;
    update: Record<string, unknown>;
    options: Record<string, unknown> | undefined;
};

class InMemoryUsers {
    readonly users = new Map<string, UserDocument>();
    readonly updateCalls: UpdateCall[] = [];
    readonly findCalls: Record<string, unknown>[] = [];
    private duplicateFailures = 0;

    failNextUpdatesWithDuplicateKey(count: number): void {
        this.duplicateFailures = count;
    }

    model(): Model<UserDocument> {
        return {
            findOne: (filter: Record<string, unknown>) => ({
                lean: async () => this.find(filter),
            }),
            updateOne: async (
                filter: Record<string, unknown>,
                update: Record<string, unknown>,
                options?: Record<string, unknown>,
            ) => this.update(filter, update, options),
            deleteOne: async ({ userId }: { userId: string }) => {
                this.users.delete(userId);
                return { acknowledged: true };
            },
        } as unknown as Model<UserDocument>;
    }

    private find(filter: Record<string, unknown>): Pick<UserDocument, 'userId' | 'sessions'> | null {
        this.findCalls.push(filter);
        const tokenHash = filter['sessions.tokenHash'];
        if (typeof tokenHash !== 'string') return null;
        const found = [...this.users.values()].find((user) =>
            user.sessions.some((session) => session.tokenHash === tokenHash));
        return found
            ? {
                userId: found.userId,
                sessions: found.sessions
                    .filter((session) => session.tokenHash === tokenHash)
                    .map((session) => ({ ...session })),
            }
            : null;
    }

    private update(
        filter: Record<string, unknown>,
        update: Record<string, unknown>,
        options?: Record<string, unknown>,
    ): { acknowledged: true } {
        this.updateCalls.push({ filter, update, options });
        if (this.duplicateFailures > 0) {
            this.duplicateFailures -= 1;
            throw { code: 11_000 };
        }

        const userId = filter.userId;
        if (typeof userId !== 'string') throw new Error('Missing userId');

        const push = update.$push as { sessions?: { $each?: UserSession[] } } | undefined;
        if (push?.sessions?.$each) {
            const session = push.sessions.$each[0];
            const existing = this.users.get(userId);
            const existingHash = existing?.sessions.some((value) => value.tokenHash === session.tokenHash);
            const hashOwnedByAnotherUser = [...this.users.values()].some((user) =>
                user.userId !== userId && user.sessions.some((value) => value.tokenHash === session.tokenHash));
            if (existingHash || hashOwnedByAnotherUser) throw { code: 11_000 };

            const user = existing ?? { userId, sessions: [] };
            user.sessions.push(session);
            user.sessions.sort((left, right) =>
                right.lastUsedAt.getTime() - left.lastUsedAt.getTime()
                || right.createdAt.getTime() - left.createdAt.getTime()
                || left.tokenHash.localeCompare(right.tokenHash));
            user.sessions.splice(10);
            this.users.set(userId, user);
            return { acknowledged: true };
        }

        const elementMatch = filter.sessions as {
            $elemMatch?: { tokenHash?: string; lastUsedAt?: { $lt?: Date } };
        } | undefined;
        const matchingSession = this.users.get(userId)?.sessions.find((session) =>
            session.tokenHash === elementMatch?.$elemMatch?.tokenHash
            && session.lastUsedAt < (elementMatch.$elemMatch.lastUsedAt?.$lt ?? new Date(0)));
        const newLastUsedAt = (update.$set as { 'sessions.$.lastUsedAt'?: Date } | undefined)?.['sessions.$.lastUsedAt'];
        if (matchingSession && newLastUsedAt) matchingSession.lastUsedAt = newLastUsedAt;
        return { acknowledged: true };
    }
}

function token(character: string): string {
    return character.repeat(32);
}

describe('authentication token helpers', () => {
    test('generates 32-character lowercase tokens and canonical SHA-256 hashes', () => {
        expect(generateRawToken()).toMatch(/^[a-f0-9]{32}$/);
        expect(hashToken('raw-authorization')).toBe('0ad4b47bdb6773e278a363a30a049248a7b3b1fd6d0e8f64c5ebd34994c1be5e');
        expect(hashToken('RAW-AUTHORIZATION')).toMatch(/^[a-f0-9]{64}$/);
    });
});

describe('createAuthenticationService', () => {
    test('atomically creates sessions with hashed deterministic coarse-LRU storage', async () => {
        const users = new InMemoryUsers();
        let now = new Date('2026-01-01T00:00:00.000Z');
        const tokens = Array.from({ length: 11 }, (_, index) =>
            index.toString(16).padStart(2, '0').repeat(16));
        const generatedTokens = [...tokens];
        const auth = createAuthenticationService({
            userModel: users.model(),
            now: () => now,
            tokenGenerator: () => tokens.shift()!,
        });

        for (let index = 0; index < 11; index += 1) {
            await auth.createSession('discord-user');
            now = new Date(now.getTime() + 1_000);
        }

        const storedSessions = users.users.get('discord-user')!.sessions;
        expect(storedSessions).toHaveLength(10);
        expect(storedSessions.map((session) => session.tokenHash)).not.toContain(hashToken(generatedTokens[0]));
        expect(storedSessions.every((session) => /^[a-f0-9]{64}$/.test(session.tokenHash))).toBe(true);

        const firstCall = users.updateCalls[0];
        expect(firstCall.filter).toEqual({
            userId: 'discord-user',
            'sessions.tokenHash': { $ne: hashToken(generatedTokens[0]) },
        });
        expect(firstCall.update).toEqual({
            $setOnInsert: { userId: 'discord-user' },
            $push: {
                sessions: {
                    $each: [{
                        tokenHash: hashToken(generatedTokens[0]),
                        createdAt: new Date('2026-01-01T00:00:00.000Z'),
                        lastUsedAt: new Date('2026-01-01T00:00:00.000Z'),
                    }],
                    $sort: { lastUsedAt: -1, createdAt: -1, tokenHash: 1 },
                    $slice: 10,
                },
            },
        });
        expect(firstCall.options).toMatchObject({ upsert: true, runValidators: true });
    });

    test('retries duplicate-key races without allowing an intra-user token duplicate', async () => {
        const users = new InMemoryUsers();
        users.failNextUpdatesWithDuplicateKey(1);
        const tokenSequence = [token('a'), token('b')];
        const auth = createAuthenticationService({
            userModel: users.model(),
            tokenGenerator: () => tokenSequence.shift()!,
        });

        await expect(auth.createSession('discord-user')).resolves.toBe(token('b'));
        expect(users.updateCalls).toHaveLength(2);
        expect(users.updateCalls.map((call) => call.filter['sessions.tokenHash']))
            .toEqual([{ $ne: hashToken(token('a')) }, { $ne: hashToken(token('b')) }]);
        expect(users.users.get('discord-user')!.sessions.map((session) => session.tokenHash))
            .toEqual([hashToken(token('b'))]);
    });

    test('authenticates by hash and atomically touches only sessions older than the interval', async () => {
        const users = new InMemoryUsers();
        const rawToken = token('c');
        const now = new Date('2026-02-01T00:20:00.000Z');
        users.users.set('discord-user', {
            userId: 'discord-user',
            sessions: [{
                tokenHash: hashToken(rawToken),
                createdAt: new Date('2026-02-01T00:00:00.000Z'),
                lastUsedAt: new Date('2026-02-01T00:00:00.000Z'),
            }],
        });
        const auth = createAuthenticationService({ userModel: users.model(), now: () => now });

        await expect(auth.authenticate(rawToken)).resolves.toEqual({
            userId: 'discord-user',
            tokenHash: hashToken(rawToken),
        });
        expect(users.findCalls).toEqual([{ 'sessions.tokenHash': hashToken(rawToken) }]);
        expect(users.updateCalls[0]).toEqual({
            filter: {
                userId: 'discord-user',
                sessions: {
                    $elemMatch: {
                        tokenHash: hashToken(rawToken),
                        lastUsedAt: { $lt: new Date('2026-02-01T00:05:00.000Z') },
                    },
                },
            },
            update: { $set: { 'sessions.$.lastUsedAt': now } },
            options: undefined,
        });

        await auth.authenticate(rawToken);
        expect(users.updateCalls).toHaveLength(1);
        expect(users.users.get('discord-user')!.sessions[0].lastUsedAt).toEqual(now);
    });

    test('returns null for unknown authorization without writing and revokes all sessions by deleting the user', async () => {
        const users = new InMemoryUsers();
        users.users.set('discord-user', { userId: 'discord-user', sessions: [] });
        const auth = createAuthenticationService({ userModel: users.model() });

        await expect(auth.authenticate(token('d'))).resolves.toBeNull();
        expect(users.updateCalls).toHaveLength(0);
        await auth.revokeAllSessions('discord-user');
        expect(users.users.has('discord-user')).toBe(false);
    });

    test('authenticates the KDF path read-only without touching session activity', async () => {
        const users = new InMemoryUsers();
        const rawToken = token('e');
        const lastUsedAt = new Date('2026-02-01T00:00:00.000Z');
        users.users.set('discord-user', {
            userId: 'discord-user',
            sessions: [{
                tokenHash: hashToken(rawToken),
                createdAt: lastUsedAt,
                lastUsedAt,
            }],
        });
        const auth = createAuthenticationService({
            userModel: users.model(),
            now: () => new Date('2026-02-01T01:00:00.000Z'),
        });

        await expect(auth.authenticateReadOnly(rawToken)).resolves.toEqual({
            userId: 'discord-user',
            tokenHash: hashToken(rawToken),
        });
        await expect(auth.authenticateReadOnly(token('f'))).resolves.toBeNull();
        expect(users.updateCalls).toHaveLength(0);
        expect(users.users.get('discord-user')!.sessions[0].lastUsedAt).toEqual(lastUsedAt);
    });
});
