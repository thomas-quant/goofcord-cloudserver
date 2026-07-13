import type { Model } from 'mongoose';

import type { SettingsService } from '../../contracts';
import { Settings, type SettingsDocument } from '../../schemas/settingsSchema';

const MAX_UPSERT_ATTEMPTS = 3;

export interface SettingsServiceOptions {
    settingsModel?: Model<SettingsDocument>;
}

function isDuplicateKeyError(error: unknown): boolean {
    return typeof error === 'object'
        && error !== null
        && 'code' in error
        && error.code === 11_000;
}

class MongooseSettingsService implements SettingsService {
    constructor(private readonly settingsModel: Model<SettingsDocument>) {}

    async save(userId: string, settings: string): Promise<void> {
        for (let attempt = 0; attempt < MAX_UPSERT_ATTEMPTS; attempt += 1) {
            try {
                await this.settingsModel.updateOne(
                    { userId },
                    {
                        $set: { settings },
                        $setOnInsert: { userId },
                    },
                    { upsert: true, setDefaultsOnInsert: false },
                );
                return;
            } catch (error) {
                if (!isDuplicateKeyError(error) || attempt === MAX_UPSERT_ATTEMPTS - 1) throw error;
            }
        }
    }

    async load(userId: string): Promise<string | null> {
        const settings = await this.settingsModel.findOne({ userId }, { _id: 0, settings: 1 }).lean();
        return settings?.settings ?? null;
    }

    async deleteForUser(userId: string): Promise<void> {
        await this.settingsModel.deleteOne({ userId });
    }
}

/** Create the settings service used by v1 routes. */
export function createSettingsService(options: SettingsServiceOptions = {}): SettingsService {
    return new MongooseSettingsService(options.settingsModel ?? Settings);
}
