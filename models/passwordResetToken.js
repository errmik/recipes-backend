import mongoose, { Schema as Schema } from 'mongoose';

const PasswordResetTokenSchema = new mongoose.Schema({
    user: {
        type: Schema.Types.ObjectId,
        ref: "user",
        required: true,
    },
    token: {
        type: String,
        required: true,
    },
    createdDate: {
        type: Date, default: Date.now
    }
})

const PasswordResetToken = mongoose.model('PasswordResetToken', PasswordResetTokenSchema)

export { PasswordResetToken } 