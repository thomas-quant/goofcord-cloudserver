import mongoose, { type Model } from 'mongoose';

export const MAX_USER_SESSIONS = 10;
export const TOKEN_HASH_PATTERN = /^[a-f0-9]{64}$/;

export interface UserSession {
    tokenHash: string;
    createdAt: Date;
    lastUsedAt: Date;
}

export interface UserDocument {
    userId: string;
    sessions: UserSession[];
}

const userSessionSchema = new mongoose.Schema<UserSession>(
    {
        tokenHash: { type: String, required: true, match: TOKEN_HASH_PATTERN },
        createdAt: { type: Date, required: true },
        lastUsedAt: { type: Date, required: true },
    },
    { _id: false },
);

const userSchema = new mongoose.Schema<UserDocument>(
    {
        userId: { type: String, required: true },
        sessions: { type: [userSessionSchema], required: true, default: [] },
    },
    { versionKey: false },
);

userSchema.path('sessions').validate(
    (sessions: UserSession[]) => {
        if (!Array.isArray(sessions) || sessions.length > MAX_USER_SESSIONS) return false;
        return new Set(sessions.map((session) => session.tokenHash)).size === sessions.length;
    },
    'Sessions must contain at most ten distinct token hashes',
);

userSchema.index({ userId: 1 }, { unique: true, name: 'users_userId_unique' });
userSchema.index({ 'sessions.tokenHash': 1 }, { unique: true, name: 'users_sessions_tokenHash_unique' });

export const User: Model<UserDocument> = (mongoose.models.User as Model<UserDocument> | undefined)
    ?? mongoose.model<UserDocument>('User', userSchema);
