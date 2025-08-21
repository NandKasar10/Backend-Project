import { asynchandler } from "../utils/asynchandler.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { ApiError } from "../utils/ApiError.js";
import {User} from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";

const generateAccessAndRefreshTokens = async(userId)=>{
    try{
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({validateBeforeSave : false});

        return { accessToken, refreshToken };

        
    } catch(err){
        throw new ApiError(500,"Something Went Wrong while generating refresh and access tokens")
    }
}


const registerUser = asynchandler( async (req,res) => {
    //steps to follow 
    //user schema laayenge aur postmann(yaa frontend) se connect kara ke user data lenge aur document bana denge aur success message sent kar denge
    // data laane ke baad validation bhi karna padega sahi daala hai ki nhi

    // get user details from frontend
    // validation - not empty
    // check if user already exists: username, email
    // check for images, check for avatar
    // upload them to cloudinary, avatar
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return res (or error if user creation got disrupted)
    


    const {fullName, email, username, password } = req.body
    // console.log("email : ", email);
    // console.log("username : ", username );

    // console.log("req.body  <-====->   " ,req.body);
    
    if (
        [fullName, email, username, password].some((field) => field?.trim() === "")
    ) {
        throw new ApiError(400, "All fields are required")
    }
    
    
    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    })
    
    if (existedUser) {
        throw new ApiError(409, "User with email or username already exists")
    }
    // console.log("before");
    
    // console.log(req.files);
    
    // console.log("after");
    const avatarLocalPath = req.files?.avatar[0]?.path;
   // const coverImageLocalPath = req.files?.coverImage[0]?.path;
    
    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
            coverImageLocalPath = req.files.coverImage[0].path
        }
        
        
    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is required")
    }
    
    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)
    
    // console.log("avatarCloudinary  <-====->   " ,avatar);
    if (!avatar) {
        throw new ApiError(400, "Avatar file is required")
    }
    
    
    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email, 
        password,
        username: username.toLowerCase()
    })
    
    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )
    
    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering the user")
    }
    
    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered Successfully")
        // {
            //     message : "Jai Shree Ram !!"
            // }
        )
    })
    
    const loginUser = asynchandler( async (req,res)=>{
        /**
         * req.body se data laayenge
         * username or email lenge
         * check karenge exists karta hai ki nhi 
         * agr haa toh abb password check karenge
         * woh bhi sahi raha toh
         * user ko access and refresh token de denge 
         * tokens ko hamlog secured cookies se bhejte hai
         * 
        */
       
       const {email, username, password} = req.body;
       
       if(!username && !email){
           throw new ApiError(400,"username or password is required !!");
        }
        
        const user = await User.findOne({
            $or:[{username},{email}]
        });
        
        if(!user){
            throw new ApiError(404,"User not exists !!");
        }
        
        const isPasswordValid = await user.isPasswordCorrect(password);
        
        if(!isPasswordValid){
            throw new ApiError(401,"Invalid user credentials (Password)");
        }
        
        const {accessToken, refreshToken} = await generateAccessAndRefreshTokens(user._id);
        
        const loggedInUser = await User.findById(user._id).select("-refreshToken -password");
        
        const options = {
            httpOnly : true,
            secure : true 
        }
        
        return res
        .status(200)
        .cookie("accessToken",accessToken,options)
        .cookie("refreshToken",refreshToken,options)
        .json(
            new ApiResponse(
                200,
                {
                    user:loggedInUser, accessToken, refreshToken
                },
                "User Logged in Successfully"
            )
        )
        
    })
    
    const logoutUser = asynchandler( async(req, res)=>{
        
        await User.findByIdAndUpdate(
            req.user._id,
            {
                $set : {
                    refreshToken : undefined
                }
            }
            ,{
                new : true
            }
        )
        
        const options = {
            httpOnly : true,
            secure : true
        }
        
        return res
        .status(200)
        .clearCookie("refreshToken",options)
        .clearCookie("accessToken",options)
        .json(new ApiResponse(
            200,
            {},
            "User Logged Out successfully !!!"
        ))
    })
    
    const refreshAccessToken = asynchandler( async(req,res)=>{
        
        const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;
        
        if(!incomingRefreshToken){
            throw new ApiError(401,"Unauthorized access. Refresh Token not available !!!");
        }
        
        try {
            const decodedToken = jwt.verify(incomingRefreshToken,process.env.REFRESH_TOKEN_SECRET);
            
            const user = await User.findById(decodedToken?._id);
            
            if(!user){
                throw new ApiError(401,"Invalid refresh Token !!!")
            }
            
            if(incomingRefreshToken !== user?.refreshToken){
                throw new ApiError(401,"Refresh-token is either expired or used !!!")
            }
            
            const {accessToken, refreshToken} = await generateAccessAndRefreshTokens(user._id);
            
            const options = {
                httpOnly : true,
                secure : true
            }
            
            return res
            .status(200)
            .cookie("accessToken",accessToken,options)
            .cookie("refreshToken",refreshToken,options)
            .json(
                new ApiResponse(200,
                    {accessToken,
                        refreshToken},
                        "refresh-token and access-token successfully refreshed !!!")
                    );
                } catch (error) {
                    throw new ApiError(401,error?.message || "Invalid refresh token !!!");
                    
    }
})

const changeCurrentPassword = asynchandler( async(req,res)=>{
    
    const {oldPassword, newPassword} = req.body;
    
    const user = await User.findById(req.user?._id);
    
    if(!user){
        throw new ApiError(400,"Unauthorized Access !!!");
    }
    
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);
    
    if(!isPasswordCorrect){
        throw new ApiError(400,"Invalid Credentials (Password) given !!!");
    }
    
    user.password = newPassword;
    await user.save({validateBeforeSave : false});
    
    return res
    .status(200)
    .json(new ApiResponse(200,{oldPassword,newPassword},"Password changed successfully !!!"));
})

const getCurrentUser = asynchandler( async(req,res)=>{
    
    return res
    .status(200)
    .json(
        new ApiResponse(
            200,
            req.user,
            "User fetched successfully"
        )
    )
})

const updateAccountDetails = asynchandler( async(req,res)=>{
    const {fullName, email}  = req.body;
    
    if(!fullName && !email){
        throw new ApiError(400,"Fullname or Email are required for changing purpose !!!")
    }
    
    const user = await User.findById(req.user?._id).select("-password");
    
    if(!user){
        throw new ApiError(400,"Unauthorized Access !!!");
    }
    
    user.fullName = fullName || user.fullName;
    
    user.email = email || user.email;
    
    await user.save({validateBeforeSave : false});
    
    return res
    .status(200)
    .json(
        new ApiResponse(200,user,"Given fields changed successfully !!!")
    );
    
    
})

const updateUserAvatar = asynchandler( async(req,res)=>{
    
    const user = await User.findById(req.user?._id);
    
    if(!user){
        throw new ApiError(400,"Unauthorized access !!!");
    }
    
    const avatarLocalPath = req.file?.path;
    
    if(!avatarLocalPath){
        throw new ApiError(400,"Avatar file is missing !!!");
    }
    
    const avatar = await uploadOnCloudinary(avatarLocalPath);
    
    if(!avatar.url){
        throw new ApiError(400,"Error while uploading avatar !!!");
    }
    
    user.avatar = avatar.url;

    await user.save({validateBeforeSave : false});

    return res
    .status(200)
    .json(
        new ApiResponse(200,user,"Avatar file changed successfully !!!")
    )

    
})

const updateUserCover = asynchandler( async(req,res)=>{
    
    const user = await User.findById(req.user?._id);
    
    if(!user){
        throw new ApiError(400,"Unauthorized access !!!");
    }
    
    const coverImageLocalPath = req.file?.path;
    
    if(!coverImageLocalPath){
        throw new ApiError(400,"Cover Image file is missing !!!");
    }
    
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);
    
    if(!coverImage.url){
        throw new ApiError(400,"Error while uploading Cover Image !!!");
    }
    
    user.coverImage = coverImage.url;

    await user.save({validateBeforeSave : false});

    return res
    .status(200)
    .json(
        new ApiResponse(200,user,"Cover file changed successfully !!!")
    )

    
})

const getUserCurrentProfile = asynchandler( async(req,res)=>{

    const {username} = req.params;

    // console.log(username);

    if(!username?.trim()){
        throw new ApiError(400,"Username not fetched successfully !!!");
    }

    const channel = await User.aggregate([
        {
            $match:{
                username : username?.toLowerCase()
            }
        },
        {
            $lookup:{
                from: "subscriptions",
                localField : "_id",  
                foreignField : "channel",
                as : "subscribers"
            }
        },
        {
            $lookup:{
                from: "subscriptions",
                localField : "_id",  
                foreignField : "subscriber",
                as : "subscribedTo"
            }
        },
        {
            $addFields : {
                subscribersCount : {
                    $size : "$subscribers"
                },
                channelsSubscribedCount : {
                    $size : "$subscribedTo"
                },
                isSubscribed : {
                    $cond : {
                        if : {$in : [req.user?._id,"$subscribers.subscriber"]},
                        then : true,
                        else : false
                    }
                }
            }
        },
        {
            $project : {
                fullName : 1,
                username : 1,
                subscribersCount : 1,
                channelsSubscribedCount : 1,
                email : 1,
                avatar : 1,
                coverImage : 1,
                isSubscribed : 1,
            }
        }

    ])

    if(!channel?.length){
        throw new ApiError(400,"Channel does not exists !!!")
    }

    // const user = await User.findOne({username});

    return res
    .status(200)
    .json(
        new ApiResponse(201,channel[0],"channel accessed successfully !!!")
    );
})

const getWatchHistory = asynchandler( async(res,req)=>{

    const user = await User.aggregate([
  {
    $match: {
    //   _id: new mongoose.Types.ObjectId(req.user._id.toString())// safer conversion
    _id : req.user?._id
    }
  },
  {
    $unwind: "$watchHistory"
  },
  {
    $lookup: {
      from: "videos",
      localField: "watchHistory",
      foreignField: "_id",
      as: "video"
    }
  },
  {
    $unwind: "$video"
  },
  {
    $lookup: {
      from: "users",
      localField: "video.owner",
      foreignField: "_id",
      as: "video.owner",
      pipeline: [
        {
          $project: {
            fullName: 1,
            username: 1,
            avatar: 1
          }
        }
      ]
    }
  },
  {
    $addFields: {
      "video.owner": { $first: "$video.owner" }
    }
  },
  {
    $group: {
      _id: "$_id",
      watchHistory: { $push: "$video" },
      username: { $first: "$username" },
      fullName: { $first: "$fullName" },
      avatar: { $first: "$avatar" }
    }
  }
]);

    if(!user){
        throw new ApiError(400,"Logging Issue Watch-History can't be fetched !!!");
    }

    if(user.length === 0){
        throw new ApiError(400,"Nothing Watch-History to be displayed !!!");
    }

    return res
    .status(200)
    .json(
        new ApiResponse(
            200,
            user[0].watchHistory,
            "Watch history fetched successfully !!!"
            
        )
    )
})

export {
    registerUser,
    loginUser,
    logoutUser, 
    refreshAccessToken, 
    changeCurrentPassword, 
    getCurrentUser, 
    updateAccountDetails, 
    updateUserAvatar, 
    updateUserCover,
    getUserCurrentProfile,
    getWatchHistory
}