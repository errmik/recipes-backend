import { StatusCodes } from "http-status-codes";
import { User } from "../models/user.js";
import { EmailValidationToken } from "../models/emailValidationToken.js";
import { BadRequestError, UnauthorizedError, ForbiddendError, EmailError } from "../errors/customError.js";
import { sendMail } from '../mail/mailer.js'
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

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
        userId: user._id,
        token: crypto.randomBytes(32).toString("hex"),
    });
    await token.save();

    //Verification url : warning when port is the default 80
    const url = `${req.protocol}://${req.hostname}:${process.env.PORT}/api/v1/auth/verify/${user.id}/${token.token}`

    //Send verification email
    const mailOptions = {
        to: user.email,
        subject: 'Verification email',
        text: `Copy paste this link to verify your account : ${url}`,
        html: `Click this link to verify your account : ${url}`
    };

    try {
        await sendMail(mailOptions);
    } catch (err) {
        //If mail cannot be sent, delete user and token
        await user.deleteOne();
        await token.deleteOne();

        throw new EmailError('Email could not be sent');
    }

    res.status(StatusCodes.OK).json({ msg: 'A verification email has been sent. Please verify your account.', name: user.name, email: user.email })
}

const verify = async (req, res) => {

    const { userId, token } = req.params;

    if (!userId || !token) {
        throw new BadRequestError("Invalid request")
    }

    const user = await User.findOne({ _id: userId });
    if (!user) {
        throw new BadRequestError("Invalid request")
    }

    const tokenInDb = await EmailValidationToken.findOne({
        userId: user._id,
        token: token,
    });

    if (!tokenInDb) {
        throw new BadRequestError("Invalid request")
    }

    //Check validity of the token ?

    //Update user : set account verified
    await User.updateOne({ _id: user._id, verified: true });

    //Delate verification token
    await EmailValidationToken.findByIdAndRemove(token._id);

    res.status(StatusCodes.OK).json({ msg: 'Your account has been verified. You can now log in.', name: user.name, email: user.email })
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
    res.cookie('jwt', refreshToken, { httpOnly: true, sameSite: 'None', secure: true, maxAge: 24 * 60 * 60 * 1000 })

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
    const payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);

    const { userId, name, email } = payload;

    if (!userId || !name || !email) {
        throw new UnauthorizedError('Invalid token')
    }

    //Find user associated with token
    const user = await User.findById(userId).exec();

    if (!user) {
        throw new UnauthorizedError('Invalid token')
    }

    //Check name and email too ? What if a user modifies his name/email ? Generate new tokens ?
    if (user.refreshToken !== refreshToken) {
        throw new UnauthorizedError('Invalid token')
    }

    const accessToken = user.createAccessToken();

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

export { register, verify, logIn, refreshToken, logOut }