import resend from "resend"

const resendClient = new resend.Resend(process.env.RESEND_API_KEY!)

interface MailOptions {
    to: string;
    subject: string;
    html: string;
}

export async function sendMail({to, subject, html}: MailOptions) {
    try {
        let data = await resendClient.emails.send({
            from: 'Acme <onboarding@resend.dev>',
            to: "sanufaridi94@gmail.com",
            subject,
            html: html
        });
        console.log("Mail sent to:", {to, data});
        return {isSuccess: true, data};
    } catch (error) {
        console.log(error)
        return {isSuccess: false, data: error};
    }
}

