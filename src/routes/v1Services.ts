import { createHash, randomBytes } from 'node:crypto';
import DiscordOauth2 from 'discord-oauth2';

import type {
    AuthenticationService,
    AuthenticatedSession,
    OAuthCodeResult,
    OAuthService,
    SettingsService,
} from '../contracts';
import type { AppConfig } from '../config';
import { Settings } from '../schemas/settingsSchema';
import { User } from '../schemas/usersSchema';
import { getUrlWithoutSlash, tokenRequest } from '../utils';

/**
 * Compatibility implementation used only until the hardened data services are
 * wired in. Keeping it behind these interfaces makes v1 a composition layer.
 */
export function createLegacyAuthenticationService(): AuthenticationService {
    return {
        async authenticate(rawAuthorization: string): Promise<AuthenticatedSession | null> {
            const user = await User.findOne({ authToken: rawAuthorization });
            return user
                ? {
                    userId: user.userId,
                    tokenHash: createHash('sha256').update(rawAuthorization).digest('hex'),
                }
                : null;
        },
        async createSession(userId: string): Promise<string> {
            const token = randomBytes(16).toString('hex');
            await User.updateOne({ userId }, { authToken: token }, { upsert: true });
            return token;
        },
        async revokeAllSessions(userId: string): Promise<void> {
            await User.deleteOne({ userId });
        },
    };
}

export function createLegacySettingsService(): SettingsService {
    return {
        async save(userId: string, settings: string): Promise<void> {
            await Settings.updateOne({ userId }, { settings }, { upsert: true });
        },
        async load(userId: string): Promise<string | null> {
            const result = await Settings.findOne({ userId });
            return result?.settings ?? null;
        },
        async deleteForUser(userId: string): Promise<void> {
            await Settings.deleteOne({ userId });
        },
    };
}

export function createDiscordOAuthService(config: AppConfig): OAuthService {
    const oauth = new DiscordOauth2({
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        redirectUri: `${getUrlWithoutSlash(config.redirectUri)}/v1/callback`,
    });
    const authorizationUrl = oauth.generateAuthUrl({ scope: ['identify'] });

    return {
        authorizationUrl: () => authorizationUrl,
        async userIdForCode(code: string): Promise<OAuthCodeResult> {
            const token = await tokenRequest(code, oauth);
            if (!token) return { kind: 'invalid_code' };
            const user = await oauth.getUser(token.access_token);
            return { kind: 'success', userId: user.id };
        },
    };
}
