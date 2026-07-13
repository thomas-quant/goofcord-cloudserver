import { describe, expect, test } from 'bun:test';
import type { Model } from 'mongoose';

import { initializeDataIndexes } from '../../src/auth';
import { Settings, type SettingsDocument } from '../../src/schemas/settingsSchema';
import { User, type UserDocument } from '../../src/schemas/usersSchema';

describe('clean-start data indexes', () => {
    test('declares the required unique indexes', () => {
        expect(User.schema.get('autoIndex')).toBe(false);
        expect(Settings.schema.get('autoIndex')).toBe(false);
        expect(User.schema.indexes()).toContainEqual([
            { userId: 1 },
            expect.objectContaining({ unique: true, name: 'users_userId_unique' }),
        ]);
        expect(User.schema.indexes()).toContainEqual([
            { 'sessions.tokenHash': 1 },
            expect.objectContaining({ unique: true, name: 'users_sessions_tokenHash_unique' }),
        ]);
        expect(Settings.schema.indexes()).toContainEqual([
            { userId: 1 },
            expect.objectContaining({ unique: true, name: 'settings_userId_unique' }),
        ]);
    });

    test('explicitly initializes both model indexes after connection', async () => {
        let usersCreated = 0;
        let settingsCreated = 0;
        await initializeDataIndexes({
            userModel: { createIndexes: async () => { usersCreated += 1; } } as Pick<Model<UserDocument>, 'createIndexes'>,
            settingsModel: { createIndexes: async () => { settingsCreated += 1; } } as Pick<Model<SettingsDocument>, 'createIndexes'>,
        });

        expect(usersCreated).toBe(1);
        expect(settingsCreated).toBe(1);
    });
});
