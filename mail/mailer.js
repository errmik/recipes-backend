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

console.log(transporter.options.host);

let sendMail = async (mailOptions) => {

    //Apply mail from
    mailOptions.from = process.env.MAIL_FROM;

    try {
        await transporter.sendMail(mailOptions);
    }
    catch (err) {
        throw new EmailError('Email could not be sent')
    }

};

export { sendMail }