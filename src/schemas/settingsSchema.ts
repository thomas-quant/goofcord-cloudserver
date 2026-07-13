import mongoose, { type Model } from 'mongoose';

export interface SettingsDocument {
    userId: string;
    settings: string;
}

const settingsSchema = new mongoose.Schema<SettingsDocument>(
    {
        userId: { type: String, required: true },
        settings: { type: String, required: true },
    },
    { versionKey: false },
);

settingsSchema.index({ userId: 1 }, { unique: true, name: 'settings_userId_unique' });

export const Settings: Model<SettingsDocument> = (mongoose.models.Settings as Model<SettingsDocument> | undefined)
    ?? mongoose.model<SettingsDocument>('Settings', settingsSchema);
