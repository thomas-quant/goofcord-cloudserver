import type { Model } from 'mongoose';

import { Settings, type SettingsDocument } from '../schemas/settingsSchema';
import { User, type UserDocument } from '../schemas/usersSchema';

export interface DataIndexOptions {
    userModel?: Pick<Model<UserDocument>, 'createIndexes'>;
    settingsModel?: Pick<Model<SettingsDocument>, 'createIndexes'>;
}

/**
 * Create clean-start indexes only after MongoDB is connected. This intentionally
 * does not synchronize or drop existing indexes, which keeps legacy migration
 * decisions explicit.
 */
export async function initializeDataIndexes(options: DataIndexOptions = {}): Promise<void> {
    await Promise.all([
        (options.userModel ?? User).createIndexes(),
        (options.settingsModel ?? Settings).createIndexes(),
    ]);
}

/** Runtime-friendly alias for the clean-start initializer. */
export async function initializeIndexes(): Promise<void> {
    await initializeDataIndexes();
}
