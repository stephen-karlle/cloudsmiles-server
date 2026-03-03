import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bodyParser from 'body-parser';
import connectToMongo from './configs/mongo.config';
// routes
import agentRoute from './routes/agent.route';
import authRoute from './routes/auth.route';
import paymentRoute from './routes/payment.route';
import stockRoute from './routes/stock.route';
import treatmentRoute from './routes/treatment.route';
import staffRoute from './routes/staff.route';
import appointmentRoute from './routes/appointment.route';
import patientRoute from './routes/patient.route';
import vendorRoute from './routes/vendor.route';
import dashboardRoute from './routes/dashboard.route';
import profileRoute from './routes/profile.route';
import reviewRoute from './routes/review.route';
import activityRoute from './routes/activity.route';
import notificationRoute from './routes/notification.route';
// auths
import cookieParser from 'cookie-parser';


dotenv.config();

const app = express();
const port = process.env.PORT || 3000;


async function startServer() {
  try {

    // Connect to MongoDB
    await connectToMongo();
    console.log('Successfully connected to MongoDB');

    // Initialize the server
    app.use(cookieParser());

    app.use(cors({
     origin: [
        'http://localhost:5173',
        'https://www.vsdentalph.com',
        'https://cloudsmiles-client-7672.onrender.com,
      ],      
      methods: ["GET", "POST", "PUT", "DELETE"],
      credentials: true,  // Allow credentials (cookies, authorization headers)
    }));

    app.use(bodyParser.json({ limit: '30mb' }));
    app.use(bodyParser.urlencoded({ limit: '30mb', extended: true }));

    // Routes
    app.use('/agent/v1', agentRoute);
    app.use('/auth/v1', authRoute);
    app.use('/payment/v1', paymentRoute);
    app.use('/stock/v1', stockRoute);
    app.use('/treatment/v1', treatmentRoute);
    app.use('/staff/v1', staffRoute);
    app.use('/appointment/v1', appointmentRoute);
    app.use('/patient/v1', patientRoute);
    app.use('/vendor/v1', vendorRoute);
    app.use('/dashboard/v1', dashboardRoute);
    app.use('/profile/v1', profileRoute);
    app.use('/review/v1', reviewRoute);
    app.use('/activity/v1', activityRoute);
    app.use('/notification/v1', notificationRoute);

    // Start server
    app.listen(port, () => {
      console.log(`Server is running on port ${port}`);
    });
  } catch (error) {
    console.error('Error starting server:', error);
    process.exit(1);  // Exit the process if there’s an error
  }
}

// Call startServer to initiate the process
startServer();
