import express from 'express'
const router = express.Router();

import { register, verify, verififyByEmail, forgotPassword, resetPassword, logIn, refreshToken, logOut } from '../controllers/auth.js'

router.post('/register', register);
router.get('/verify/:userId/:token', verify);
router.post('/verifyByEmail', verififyByEmail);
router.post('/forgotPassword', forgotPassword);
router.post('/resetPassword', resetPassword);
router.post('/login', logIn);
router.get('/refreshToken', refreshToken);
router.get('/logout', logOut);

export { router as authRouter };