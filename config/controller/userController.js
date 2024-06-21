import { userModel } from "../config/models/userModel.js.js";
import {error,success} from "../utills/responseWrapper.js";
import bcrypt from "bcrypt";
import { generateAccessToken } from "../services/generateAccessToken.js";


export async function registerController(req,res){
    try {
       const {name,email,password} = req.body;

       if(!name || !email || !password){
        return res.send(error(404,"all fields are required"));
       }
      const existingUser = await userModel.findOne({email:email});
      if(existingUser){
        return res.send(error(409,"you have registered,please login"));
      }
      const hashedPassword = await bcrypt.hash(password,10);
      const newUser = new userModel({name,email,password:hashedPassword});
       await newUser.save();
       return res.send(success(200,"user Registered successfully")); 
    } catch (err) {
        return res.send(error(500,err.message));
    }
}

export async function loginController(req,res){
    try {
        const {email,password} = req.body;
        if( !email || !password){
            return res.send(error(404,"all fields are required"));
           }
        const user = await userModel.findOne({email});
      
        if(!user){
            return res.send(error(409,"user not exist please login"));
        }
        const match = await  bcrypt.compare(password,user.password);
        
        if(!match){
            return res.send(error(404,"password not matched, please enter right password"))
        }
        const token = generateAccessToken({...user});
        
        return res.send(success(200,token,"user login successfully"));

    } catch (err) {
        return res.send(error(500,err.message));
    }
}