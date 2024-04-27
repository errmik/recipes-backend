import mongoose, { Schema as Schema, model } from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Name is required'],
        maxlength: 50,
        minlength: 3,
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        match: [
            /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
            'Please provide a valid email',
        ],
        unique: true,
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: 6,
    },
    verified: {
        type: Boolean,
        default: false,
    },
    refreshToken: {
        type: String,
        required: false,
    },
})

// UserSchema.pre('save', async function () {
//     const salt = await bcrypt.genSalt(10)
//     this.password = await bcrypt.hash(this.password, salt)
// })

UserSchema.methods.createAccessToken = function () {
    return jwt.sign(
        { userId: this._id, name: this.name, email: this.email },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRATION,
        }
    )
}

UserSchema.methods.createRefreshToken = function () {
    return jwt.sign(
        { userId: this._id, name: this.name, email: this.email },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRATION,
        }
    )
}

UserSchema.methods.checkPassword = async function (canditatePassword) {
    const isMatch = await bcrypt.compare(canditatePassword, this.password)
    return isMatch
}

const User = mongoose.model('User', UserSchema)

export { User } 