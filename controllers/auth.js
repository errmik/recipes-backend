import { StatusCodes } from "http-status-codes";
import { User } from "../models/user.js";
import { EmailValidationToken } from "../models/emailValidationToken.js";
import { PasswordResetToken } from "../models/passwordResetToken.js"
import { BadRequestError, UnauthorizedError, ForbiddendError, EmailError } from "../errors/customError.js";
import { sendVerificationMail, sendPasswordResetMail } from '../mail/mailer.js'
import { transformTemplate } from "../templates/templates.js";
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

//TODO : rate limiting on all those controller
//implement lock account
//send email on password reset

const register = async (req, res) => {

    const { email, name, password } = req.body

    if (!email || !name || !password) {
        throw new BadRequestError('Please provide email, name and password')
    }

    let user = await User.findOne({ email }).exec();

    if (user) {
        throw new UnauthorizedError('User already exists')
    }

    //Hash password
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)

    //Create new user
    user = new User({ name, email, password: hashedPassword });
    await user.save()

    //Create verification token
    const token = new EmailValidationToken({
        user: user._id,
        token: crypto.randomBytes(32).toString("hex"),
    });
    await token.save();

    //Verification url
    const urlPort = process.env.PORT != 80 ? `:${process.env.PORT}` : ''
    const url = `${req.protocol}://${req.hostname}${urlPort}/api/v1/auth/verify/${user.id}/${token.token}`

    try {
        await sendVerificationMail(user, url);
    } catch (err) {
        //If mail cannot be sent, delete user and token
        await user.deleteOne();
        await token.deleteOne();

        throw new EmailError('Email could not be sent');
    }

    res.status(StatusCodes.OK).json({ msg: 'A verification email has been sent. Please verify your account.', name: user.name, email: user.email })
}

//Send verification email one more time
const verififyByEmail = async (req, res) => {

    const { email } = req.body

    if (!email) {
        throw new BadRequestError('Please provide email')
    }

    let user = await User.findOne({ email }).exec();

    if (!user) {
        throw new UnauthorizedError('User not found')
    }

    if (user.verified) {
        throw new UnauthorizedError('User already verified')
    }

    //Delete all tokens already associated with the user
    await EmailValidationToken.deleteMany({ user: user._id })

    //Create verification token
    const token = new EmailValidationToken({
        user: user._id,
        token: crypto.randomBytes(32).toString("hex"),
    });
    await token.save();

    //Verification url : warning when port is the default 80
    const urlPort = process.env.PORT != 80 ? `:${process.env.PORT}` : ''
    const url = `${req.protocol}://${req.hostname}${urlPort}/api/v1/auth/verify/${user.id}/${token.token}`

    try {
        await sendVerificationMail(user, url);
    } catch (err) {
        //If mail cannot be sent, delete token
        await token.deleteOne();
        //don't delete the user though...

        throw new EmailError('Email could not be sent');
    }

    res.status(StatusCodes.OK).json({ msg: 'A verification email has been sent. Please verify your account.', name: user.name, email: user.email })
}

const verify = async (req, res) => {

    const { userId, token } = req.params;

    if (!userId || !token) {
        throw new BadRequestError("Invalid request")
    }

    let user = await User.findById(userId).exec();
    if (!user) {
        throw new BadRequestError("Invalid request")
    }

    if (user.verified) {
        throw new UnauthorizedError('User already verified')
    }

    const tokenInDb = await EmailValidationToken.findOne({
        user: user._id,
        token: token,
    });

    if (!tokenInDb) {
        throw new BadRequestError("Invalid request")
    }

    //TODO : Check validity of the token ? What if the token is invalid ? Delete, Gen a new one and resend an email

    //Update user : set account verified
    user.verified = true
    await user.save();

    //Delete verification token
    await EmailValidationToken.findByIdAndDelete(tokenInDb._id);

    //TODO : renvoyer un html de verification
    var result = await transformTemplate('./templates/activated.html', { FirstName: user.name, LoginLink: process.env.RECIPES_UI_URL })
    
    res.status(StatusCodes.OK).send(result)
    //res.status(StatusCodes.OK).json({ msg: 'Your account has been verified. You can now log in.', name: user.name, email: user.email })
}

const forgotPassword = async (req, res) => {

    const { email } = req.body;

    if (!email) {
        throw new BadRequestError('Please provide email')
    }

    let user = await User.findOne({ email }).exec();

    if (!user) {
        throw new UnauthorizedError('User not found')
    }

    if (user.verified) {
        throw new UnauthorizedError('User already verified')
    }

    //Delete previous password reset tokens
    PasswordResetToken.deleteMany({ user: user._id })

    //Create password reset token
    const token = new PasswordResetToken({
        user: user._id,
        token: crypto.randomBytes(32).toString("hex"),
    });
    await token.save();

    //Verification url : warning when port is the default 80
    const urlPort = process.env.PORT != 80 ? `:${process.env.PORT}` : ''
    const url = `${req.protocol}://${req.hostname}${urlPort}/api/v1/auth/resetPassword/${user.id}/${token.token}`

    try {
        await sendPasswordResetMail(user, url);
    } catch (err) {
        //If mail cannot be sent, delete token
        await token.deleteOne();
        //don't delete the user though...

        throw new EmailError('Email could not be sent');
    }


    res.status(StatusCodes.OK).json({ msg: 'Your account has been verified. You can now log in.', name: user.name, email: user.email })
}

const resetPassword = async (req, res) => {

    const { userId, token, password } = req.body;

    if (!userId || !token) {
        throw new BadRequestError('User id or token not available')
    }

    if (!password) {
        throw new BadRequestError('Please provide password')
    }

    let user = await User.findById(userId).exec();

    if (!user) {
        throw new UnauthorizedError('User not found')
    }

    if (!user.verified) {
        throw new UnauthorizedError('User not verified')
    }

    //Check password reset token
    const tokenInDb = await PasswordResetToken.findOne({
        user: user._id,
        token: token,
    });

    if (!tokenInDb) {
        throw new BadRequestError("Invalid request")
    }

    //Hash password
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)

    //Update user : Change password
    user.password = hashedPassword
    await user.save()

    //Delete verification token
    await PasswordResetToken.findByIdAndDelete(tokenInDb._id);

    res.status(StatusCodes.OK).json({ msg: 'Your password has been modified. You can now log in.', name: user.name, email: user.email })
}

const logIn = async (req, res) => {

    const { email, password } = req.body

    if (!email || !password) {
        throw new BadRequestError('Please provide email and password')
    }

    const user = await User.findOne({ email }).exec();

    if (!user) {
        throw new UnauthorizedError('Invalid user')
    }

    var passwordChecked = await user.checkPassword(password);

    if (!passwordChecked) {
        throw new UnauthorizedError('Invalid password')
    }

    if (!user.verified) {
        throw new UnauthorizedError('Account has not been verified.')
    }

    const accessToken = user.createAccessToken();
    const refreshToken = user.createRefreshToken();

    //Save refresh token in database
    user.refreshToken = refreshToken;
    await user.save();

    //Refresh token is sent in a http only cookie, so it should not be accessible from frontend js
    res.cookie(process.env.REFRESH_TOKEN_COOKIE || 'recipesJwtRefresh', refreshToken, { httpOnly: true, sameSite: 'None', secure: true, maxAge: 24 * 60 * 60 * 1000 })

    //Access token is sent in json response. Storing it in the most secure way is the frontend responsability
    res.status(StatusCodes.OK).json({ userId: user._id, name: user.name, email: user.email, accessToken })
}

const refreshToken = async (req, res) => {

    if (!req.cookies?.jwt) {
        throw new UnauthorizedError('No refresh token');
    }

    var refreshToken = req.cookies.jwt;

    //console.log(refreshToken)

    //Check refresh token
    let payload

    try {
        payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    } catch (err) {
        throw new BadRequestError('Invalid token')
    }

    const { userId, name, email } = payload;

    if (!userId || !name || !email) {
        throw new UnauthorizedError('Invalid token')
    }

    //Find user associated with token
    const user = await User.findById(userId).exec();

    if (!user) {
        throw new UnauthorizedError('Invalid token')
    }

    //Check user validity ? blocked ? verified ?

    //Check name and email too ? What if a user modifies his name/email ? Generate new tokens ?
    if (user.refreshToken !== refreshToken) {
        throw new UnauthorizedError('Invalid token')
    }

    const accessToken = user.createAccessToken();

    //Renew the refresh token.
    //TODO : check if the cookie is not sent twice. If so, delete cookie first
    // const refreshToken = user.createRefreshToken();

    // //Save refresh token in database
    // user.refreshToken = refreshToken;
    // await user.save();

    // //Refresh token is sent in a http only cookie, so it should not be accessible from frontend js
    //// Clearing the cookie
    //res.clearCookie('title');
    // res.cookie('jwt', refreshToken, { httpOnly: true, sameSite: 'None', secure: true, maxAge: 24 * 60 * 60 * 1000 })

    //Access token is sent in json response. Storing it in the most secure way is the frontend responsability
    res.status(StatusCodes.OK).json({ userId: user._id, name: user.name, email: user.email, accessToken })
}

const logOut = async (req, res) => {

    if (!req.cookies?.jwt) {
        //No cookie ? nothing to do
        return res.sendStatus(StatusCodes.NO_CONTENT);
    }

    var refreshToken = req.cookies.jwt;

    let payload = '';

    try {
        payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    } catch (error) {
        //Invalid refresh token ? Clear cookies, and that's it
        res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true })
        return res.sendStatus(StatusCodes.NO_CONTENT);
    }

    //Check refresh token
    const { userId, name, email } = payload;

    if (!userId) {
        //Invalid refresh token ? Clear cookies, and that's it
        res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true })
        return res.sendStatus(StatusCodes.NO_CONTENT);
    }

    //Find user associated with token
    const user = await User.findById(userId).exec();

    if (!user) {
        //No user ? Clear cookies, and that's it
        res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true })
        return res.sendStatus(StatusCodes.NO_CONTENT);
    }

    //What if a user modifies his name/email ? Generate new tokens ?
    if (user.refreshToken !== refreshToken) {
        //Strange case... Clear cookies, and that's it
        res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true })
        return res.sendStatus(StatusCodes.NO_CONTENT);
    }

    //raz refresh token in database
    user.refreshToken = '';
    await user.save();

    //Clear cookie
    res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true })
    return res.sendStatus(StatusCodes.NO_CONTENT);
}

export { register, verify, verififyByEmail, forgotPassword, resetPassword, logIn, refreshToken, logOut }