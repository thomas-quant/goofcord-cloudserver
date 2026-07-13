import { createHash, randomBytes } from 'node:crypto';

export const RAW_TOKEN_PATTERN = /^[a-f0-9]{32}$/;

/** Generate the client-facing token format retained for GoofCord compatibility. */
export function generateRawToken(): string {
    return randomBytes(16).toString('hex');
}

/** Hash raw authorization values before they are used in any database query. */
export function hashToken(rawToken: string): string {
    return createHash('sha256').update(rawToken, 'utf8').digest('hex');
}
