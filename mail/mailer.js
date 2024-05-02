import nodemailer from 'nodemailer'
import { EmailError } from "../errors/customError.js"

var smtpConfig = {
    host: process.env.MAIL_HOST,
    port: process.env.MAIL_PORT,
    secure: true, // use SSL
    auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS
    }
};

const transporter = nodemailer.createTransport(smtpConfig);

transporter.verify((err, success) => {
    if (err)
        throw new EmailError("Connexion to mail service failed")

    if (success)
        console.log('Connected to mail service');
});

const sendMail = async (mailOptions) => {

    //Apply mail from
    mailOptions.from = process.env.MAIL_FROM;

    try {
        await transporter.sendMail(mailOptions);
    }
    catch (err) {
        throw new EmailError('Email could not be sent')
    }

};

const sendVerificationMail = async (user, url) => {

    ///TODO : templating engine

    //Send verification email
    const mailOptions = {
        to: user.email,
        subject: 'Verification email',
        text: `Copy paste this link to verify your account : ${url}`,
        html: `Click this link to verify your account : ${url}`
    };

    await sendMail(mailOptions);

};

const sendPasswordResetMail = async (user, url) => {

    ///TODO : templating engine
    
    //must redirect to a frontend page, that will post to resetpassword

    //Send verification email
    const mailOptions = {
        to: user.email,
        subject: 'Reset password email',
        text: `Copy paste this link to reset your password : ${url}`,
        html: `Click this link to reset your password : ${url}`
    };

    await sendMail(mailOptions);

};

export { sendMail, sendVerificationMail, sendPasswordResetMail }