import express from "express";
import dotenv from "dotenv";
import connectDB from "./config/db.js";
import userRouter from "./routes/userRoutes.js";
dotenv.config();
connectDB();
const app = express();
app.use(express.json());
 app.use('/user',userRouter);
const port = process.env.PORT || 3000;

app.listen(port,()=>{
    console.log(`server running on port ${port}`);
})