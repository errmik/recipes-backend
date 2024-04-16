import { StatusCodes } from "http-status-codes";
import { User } from "../models/user.js";
import { BadRequestError, UnauthorizedError, ForbiddendError } from "../errors/customError.js";
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const register = async (req, res) => {
    const { email, name, password } = req.body

    if (!email || !name || !password) {
        throw new BadRequestError('Please provide email, name and password')
    }

    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)

    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save()

    res.status(StatusCodes.OK).json({ msg: 'registered', name: newUser.name, email: newUser.email })
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

    console.log(refreshToken)

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

export { register, logIn, refreshToken, logOut }