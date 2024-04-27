import mongoose, { Schema as Schema, model } from 'mongoose';

const EmailValidationTokenSchema = new mongoose.Schema({
    userId: {
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

const EmailValidationToken = mongoose.model('EmailValidationToken', EmailValidationTokenSchema)

export { EmailValidationToken } 