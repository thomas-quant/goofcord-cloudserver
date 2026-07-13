import DiscordOauth2 from 'discord-oauth2';

import type { OAuthCodeResult, OAuthService } from '../contracts';
import type { AppConfig } from '../config';
import { getUrlWithoutSlash, tokenRequest } from '../utils';

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
