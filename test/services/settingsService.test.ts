import { describe, expect, test } from 'bun:test';
import type { Model } from 'mongoose';

import { createSettingsService } from '../../src/services/settings';
import type { SettingsDocument } from '../../src/schemas/settingsSchema';

type UpdateCall = {
    filter: Record<string, unknown>;
    update: Record<string, unknown>;
    options: Record<string, unknown> | undefined;
};

class InMemorySettings {
    readonly values = new Map<string, string>();
    readonly updateCalls: UpdateCall[] = [];
    private duplicateFailures = 0;

    failNextUpdatesWithDuplicateKey(count: number): void {
        this.duplicateFailures = count;
    }

    model(): Model<SettingsDocument> {
        return {
            updateOne: async (
                filter: Record<string, unknown>,
                update: Record<string, unknown>,
                options?: Record<string, unknown>,
            ) => {
                this.updateCalls.push({ filter, update, options });
                if (this.duplicateFailures > 0) {
                    this.duplicateFailures -= 1;
                    throw { code: 11_000 };
                }
                const userId = filter.userId as string;
                this.values.set(userId, (update.$set as { settings: string }).settings);
                return { acknowledged: true };
            },
            findOne: ({ userId }: { userId: string }) => ({
                lean: async () => {
                    const settings = this.values.get(userId);
                    return settings === undefined ? null : { settings };
                },
            }),
            deleteOne: async ({ userId }: { userId: string }) => {
                this.values.delete(userId);
                return { acknowledged: true };
            },
        } as unknown as Model<SettingsDocument>;
    }
}

describe('createSettingsService', () => {
    test('uses an atomic one-document-per-user upsert and retries a concurrent first-write race', async () => {
        const settings = new InMemorySettings();
        settings.failNextUpdatesWithDuplicateKey(1);
        const service = createSettingsService({ settingsModel: settings.model() });

        await service.save('discord-user', 'first');
        await service.save('discord-user', 'replacement');

        expect(settings.values).toEqual(new Map([['discord-user', 'replacement']]));
        expect(settings.updateCalls[0]).toEqual({
            filter: { userId: 'discord-user' },
            update: {
                $set: { settings: 'first' },
                $setOnInsert: { userId: 'discord-user' },
            },
            options: { upsert: true, setDefaultsOnInsert: false },
        });
        expect(settings.updateCalls).toHaveLength(3);
    });

    test('loads opaque settings and supports idempotent deletion before session revocation', async () => {
        const settings = new InMemorySettings();
        const service = createSettingsService({ settingsModel: settings.model() });

        await expect(service.load('discord-user')).resolves.toBeNull();
        await service.save('discord-user', 'opaque-settings-payload');
        await expect(service.load('discord-user')).resolves.toBe('opaque-settings-payload');
        await service.deleteForUser('discord-user');
        await service.deleteForUser('discord-user');
        await expect(service.load('discord-user')).resolves.toBeNull();
    });
});
