import mongoose, { Schema as Schema } from 'mongoose';

const EmailValidationTokenSchema = new mongoose.Schema({
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

const EmailValidationToken = mongoose.model('EmailValidationToken', EmailValidationTokenSchema)

export { EmailValidationToken } 