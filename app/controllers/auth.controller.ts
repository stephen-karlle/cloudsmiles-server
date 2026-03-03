import { Request, Response, NextFunction } from 'express';
import { removeAccessTokenCookie, setAccessTokenCookie } from '../utils/cookie.utils';
import { sendRecoveryLink, sendVerificationCode } from '../helpers/resend/transporters';
import { getFullName } from '../utils/name.utils';
import passport from 'passport';
import CredentialsModel from '../schemas/mongo/credential.schema';
import PatientModel from '../schemas/mongo/patient.schema';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import AssistantModel from '../schemas/mongo/assistant.schema';
import AdminModel from '../schemas/mongo/admin.schema';
import DentistModel from '../schemas/mongo/dentist.schema';

dotenv.config()

const saltRounds = 10;
export const googleAuth = passport.authenticate('google', { scope: ['profile', 'email'] });

export const googleAuthCallback = (req: Request, res: Response) => {
  const token = jwt.sign(
    { user: req.user},
    process.env.JWT_SECRET || '',
    { expiresIn: "1h" },
  );
  res.cookie('jwtToken', token);
  res.redirect("http://localhost:5173");
};
export const logout = (req: Request, res: Response, next: NextFunction) => {
  removeAccessTokenCookie(res)
  return res.status(200).json({ message: 'Logged out successfully' });

};
export const validateEmail = async (req: Request, res: Response) => {
  const { email } = req.params;
  console.log(email)
  try {
    const existingUser = await CredentialsModel.findOne({ credentialEmail: email });
    if (existingUser) {
      res.status(401).json({ message: "Email already exists!" });
    } else {
      res.status(200).json({ message: "Email is available!" });
    }
  } catch (error) {
    res.status(500).json({ message: error });
  }
}
export const signUpLocal = async (req: Request, res: Response) => {
  const { patientFullName, patientDateOfBirth, patientAddress, patientGender } = req.body.patientData;
  const { credentialEmail, credentialPhoneNumber, credentialPassword } = req.body.credentialData;
  try {
    const patientResult = await PatientModel.create({
      patientFullName: patientFullName,
      patientDateOfBirth: patientDateOfBirth,
      patientGender: patientGender,
      patientAddress: patientAddress,
      patientStatus: "Pending",
    })

    const hashedPassword = await bcrypt.hashSync(credentialPassword, saltRounds);
    
    const credentialOTP = Math.floor(100000 + Math.random() * 900000);
    const existingUser = await CredentialsModel.create({
      credentialProvider: "local",
      credentialEmail: credentialEmail,
      credentialPhoneNumber: credentialPhoneNumber,
      credentialPassword: hashedPassword,
      credentialRole: "patient",
      credentialPatientId: patientResult._id,
      credentialOTP: credentialOTP,
    })

    await PatientModel.updateOne({ _id: patientResult._id }, { $set: { patientCredentialId: existingUser._id } });

    const fullName = await getFullName(existingUser);
    const firstName = fullName.split(" ")[0];
    const otp = Math.floor(100000 + Math.random() * 900000);

    sendVerificationCode(credentialEmail, firstName, otp);

    await CredentialsModel.updateOne({ credentialEmail: credentialEmail }, { $set: { 
      credentialOTP: otp,
      isLoginTokenExpired: false,
    } });
    const token = jwt.sign(
      {
        _id: existingUser._id,
        purpose: "verification",
      },
      process.env.JWT_SECRET || "",
      { expiresIn: "10m" }
    );    
    res.status(200).json(token);
  } catch (error) {
    res.status(500).json({ message: error });
  }
}
export const verifyUser = async (req: Request, res: Response) => {
  const token = req.cookies.accessToken; 

  // Check if token is provided
  if (!token || token === undefined) {
    return  res.status(200).json({ userRole: "guest" });
  }

  try {
    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as { _id: string };

    // Check if user exists
    const existingUser = await CredentialsModel.findById(decoded._id);
    if (!existingUser) {
      return res.status(201).json({ message: "User does not exist!" });
    }


    let user = {
      _id: "",
      avatar: "",
      fullName: "",
      gender: "",
      dateOfBirth: new Date(),
      address: "",
      phoneNumber: existingUser.credentialPhoneNumber,
      email: existingUser.credentialEmail,
      role: existingUser.credentialRole,
    }

    if (existingUser.credentialRole === "dentist") {
      const dentist = await DentistModel.findById(existingUser.credentialDentistId);
    
      if (!dentist) {
        return res.status(202).json({ message: "Dentist does not exist!" });
      }
      user._id = String(dentist._id)
      user.avatar = dentist.dentistAvatar
      user.fullName = dentist.dentistFullName
      user.gender = dentist.dentistGender
      user.dateOfBirth = dentist.dentistDateOfBirth
      user.address = dentist.dentistAddress
    }


    if (existingUser.credentialRole === "patient") {
      const patient = await PatientModel.findById(existingUser.credentialPatientId);
      if (!patient) {
        return res.status(202).json({ message: "Patient does not exist!" });
      }
      user._id = String(patient._id)
      user.avatar = patient.patientAvatar
      user.fullName = patient.patientFullName
      user.gender = patient.patientGender
      user.dateOfBirth = patient.patientDateOfBirth
      user.address = patient.patientAddress
    }


    if (existingUser.credentialRole === "assistant") {
      const assistant = await AssistantModel.findById(existingUser.credentialAssistantId);
      if (!assistant) {
        return res.status(202).json({ message: "Assistant does not exist!" });
      }
      user._id = String(assistant._id)
      user.avatar = assistant.assistantAvatar
      user.fullName = assistant.assistantFullName
      user.gender = assistant.assistantGender
      user.dateOfBirth = assistant.assistantDateOfBirth
      user.address = assistant.assistantAddress
    }

    if (existingUser.credentialRole === "admin") {
      const admin = await AdminModel.findById(existingUser.credentialAdminId);
    
      if (!admin) {
        return res.status(202).json({ message: "Admin does not exist!" });
      }

      user._id = String(admin._id)
      user.avatar = admin.adminAvatar
      user.fullName = admin.adminFullName
      user.gender = admin.adminGender
      user.dateOfBirth = admin.adminDateOfBirth
      user.address = admin.adminAddress
    }

    // Return the user's role
    res.status(200).json({ 
      userRole: existingUser.credentialRole,
      userData: user,
     });
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      // Token verification failed
      return res.status(401).json({ message: "Invalid token!" });
    }
    // Other server errors
    console.error("Error verifying role:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};
export const loginLocal = async (req: Request, res: Response ) => {
  const { email, password } = req.body;
  try {
    const existingUser = await CredentialsModel.findOne({ credentialEmail: email });
    if (!existingUser) {
      return res.status(402).json({ message: "Email does not exist!" });
    }
    const isPasswordValid = await bcrypt.compare(password, existingUser.credentialPassword);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid password!" });
    }

    
    const fullName = await getFullName(existingUser);
    const firstName = fullName.split(" ")[0];
    const otp = Math.floor(100000 + Math.random() * 900000);

    sendVerificationCode(email, firstName, otp);

    await CredentialsModel.updateOne({ credentialEmail: email }, { $set: { 
      credentialOTP: otp,
      isLoginTokenExpired: false,
    } });
    const token = jwt.sign(
      {
        _id: existingUser._id,
        purpose: "verification",
      },
      process.env.JWT_SECRET || "",
      { expiresIn: "10m" }
    );

    res.status(200).json(token);

  } catch(error) {
    res.status(500).json({ message: error });
  }
}
export const getPatient = async (req: Request, res: Response) => {
  const token = req.cookies.accessToken; 

  if (!token) {
    return res.status(401).json({ message: "No token provided!" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as { id: string };

    const existingUser = await CredentialsModel.findById(decoded.id);


    if (!existingUser) {
      return res.status(401).json({ message: "User does not exist!" });
    }

    const patientResult = await PatientModel.findById(existingUser.credentialPatientId);

    res.status(200).json(patientResult);
  } catch (error) {
    res.status(500).json({ message: error });
  }
};
export const recoverAccount = async (req: Request, res: Response) => {
  const { email } = req.body;
  try {
    const existingUser = await CredentialsModel.findOne({ credentialEmail: email });
    if (!existingUser) {
      return res.status(401).json({ message: "Email does not exist!" });
    }
    const token = jwt.sign(
      {
        _id: existingUser._id,
        email: existingUser.credentialEmail,
        purpose: "recovery",
      },
      process.env.JWT_SECRET || "",
      { expiresIn: "15m" }
    );


    await CredentialsModel.updateOne({ credentialEmail: email }, { $set: { isRecoveryTokenExpired: false } });

    const fullName = await getFullName(existingUser);
    const firstName = fullName.split(" ")[0];
    // Create the magic link
    const recoveryLink = `${process.env.FRONTEND_URL}/reset?token=${token}`;
    await sendRecoveryLink(email, firstName, recoveryLink);

    res.status(200).json({ message: "Recovery link sent successfully!" });
  } catch (error) {
    res.status(500).json({ message: error });
  }
         
}
export const verifyRecoveryToken = async (req: Request, res: Response) => {
  const { token } = req.params;
  if (!token) {
    return res.status(401).json({ message: "No token provided!" });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as { email: string, exp: number, purpose: string };

    if (!decoded) {
      return res.status(401).json({ message: "Invalid token!" });
    }

    console.log(decoded)

    if (decoded.purpose !== "recovery") {
      return res.status(401).json({ message: "Invalid token!" });
    }

    const credentialResult = await CredentialsModel.findOne({ credentialEmail: decoded.email});

    if (!credentialResult) {
      console.log("User does not exist!")
      return res.status(401).json({ message: "Token expired!" });
    }

    if (credentialResult.isRecoveryTokenExpired) {
      return res.status(401).json({ message: "Token expired!" });
    }

    if (decoded.exp < Date.now() / 1000) {
      return res.status(401).json({ message: "Token expired!" });
    }

    const existingUser = await CredentialsModel.findOne({ credentialEmail: decoded.email });
    if (!existingUser) {
      return res.status(401).json({ message: "User does not exist!" });
    }
    
    res.status(200).json({ message: "Token verified successfully!" });
  } catch (error) {
    res.status(500).json({ message: error });
  }
}
export const resetPassword = async (req: Request, res: Response) => {
  const { token, newPassword } = req.body;
  if (!token) {
    return res.status(401).json({ message: "No token provided!" });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as { email: string, purpose: string };

    if (!decoded) {
      return res.status(401).json({ message: "Invalid token!" });
    }

    if (decoded.purpose !== "recovery") {
      return res.status(401).json({ message: "Invalid token!" });
    }

    const existingUser = await CredentialsModel.findOne({ credentialEmail: decoded.email });
    if (!existingUser) {
      return res.status(401).json({ message: "User does not exist!" });
    }

    const oldPassword = existingUser.credentialPassword;
    const isPasswordValid = await bcrypt.compare(newPassword, oldPassword);
    if (isPasswordValid) {
      return res.status(401).json({ message: "You cannot use the same password as your current password!" });
    }

    const hashedPassword = bcrypt.hashSync(newPassword, saltRounds);
    await CredentialsModel.updateOne({ credentialEmail: decoded.email }, { $set: { 
      credentialPassword: hashedPassword,
      isRecoveryTokenExpired: true,
    } });

    res.status(200).json({ message: "Password reset successfully!" });
  } catch (error) {
    res.status(500).json({ message: error });
  }
}
export const changePassword = async (req: Request, res: Response) => {
  const { oldPassword, newPassword } = req.body;
  const token = req.cookies.accessToken;

  if (!token) {
    return res.status(401).json({ message: "No token provided!" });
  }

  const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as { _id: string };
  if (!decoded) {
    return res.status(401).json({ message: "Invalid token!" });
  }

  const userId = decoded._id;

  try {
    const existingUser = await CredentialsModel.findById(userId);

    if (!existingUser) {
      return res.status(401).json({ message: "User does not exist!" });
    }

    if (oldPassword === newPassword) {
      return res.status(401).json({ message: "You cannot use the same password as your current password!" });
    }

    const isPasswordValid = await bcrypt.compare(oldPassword, existingUser.credentialPassword);

    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid password!" });
    }

    const hashedPassword = bcrypt.hashSync(newPassword, saltRounds);
    await CredentialsModel.updateOne({ _id: userId }, { $set: {
      credentialPassword: hashedPassword,
    }})

    res.status(200).json({ message: "Password changed successfully!" });

  } catch (error) {
    res.status(500).json({ message: error });
  }
}
export const verifyLoginToken  = async (req: Request, res: Response) => {
  const token = req.params.token 

  if (!token) {
    return res.status(401).json({ message: "No token provided!" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as { _id: string, purpose: string };
    

    if (!decoded) {
      return res.status(401).json({ message: "Invalid token!" });
    }

    if (decoded.purpose !== "verification") {
      return res.status(401).json({ message: "Invalid token!" });
    }

    const existingUser = await CredentialsModel.findById(decoded._id)
    
    if (!existingUser) {
      return res.status(401).json({ message: "User does not exist!" });
    }

    if (existingUser.isLoginTokenExpired) {
      return res.status(401).json({ message: "Token expired!" });
    }

    res.status(200).json(existingUser.credentialEmail);
  } catch (error) {
    res.status(500).json({ message: error });
  }
}
export const verifyOtp = async (req: Request, res: Response) => {
  const { email, otp } = req.body;
  try {
    const existingUser = await CredentialsModel.findOne({ credentialEmail: email });

    if (existingUser && Number(existingUser.credentialOTP) === Number(otp)) {
      const existingUser = await CredentialsModel.findOneAndUpdate({ credentialEmail: email }, { $set: { credentialOTP: null } });
      if (!existingUser) {
        return res.status(401).json({ message: "User does not exist!" });
      }
      setAccessTokenCookie(res, existingUser)
      await CredentialsModel.findByIdAndUpdate(existingUser._id, { isLoginTokenExpired: true });
      return res.status(200).json(existingUser.credentialRole);
    }
    res.status(401).json({ message: "Invalid OTP!" });
    
  } catch (error) {
    res.status(500).json({ message: error });
  }
    
}
export const resendOTP = async (req: Request, res: Response) => {
  const { email } = req.body;
  try {
    const existingUser = await CredentialsModel.findOne({ credentialEmail: email })

    if (!existingUser) {
      return res.status(401).json({ message: "Email does not exist!" });
    }

    const credentialOTP = Math.floor(100000 + Math.random() * 900000);
    console.log(credentialOTP)
    await CredentialsModel.updateOne({ credentialEmail: email }, { $set: { credentialOTP } });

    const fullName = await getFullName(existingUser);
    const firstName = fullName.split(" ")[0];

    await sendVerificationCode(email,firstName, credentialOTP);
    res.status(200).json({ message: "OTP sent successfully!" });

  } catch (error) {
    res.status(500).json({ message: error });
  }
}
