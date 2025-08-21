import { Router } from "express";
import { changeCurrentPassword, getCurrentUser, getUserCurrentProfile, getWatchHistory, loginUser, logoutUser, refreshAccessToken, registerUser, updateAccountDetails, updateUserAvatar, updateUserCover } from "../controllers/user.controller.js";
import { upload } from "../middlewares/multer.middleware.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";


const router = Router();

router.route("/register").post(
    upload.fields([
        {
            name : "avatar",
            maxCount : 1
        },
        {
            name : "coverImage",
            maxCount : 1
        }
    ]),
    registerUser
)

router.route("/login").post(upload.none(),loginUser)

router.route("/logout").post(
    verifyJWT,
    logoutUser
)

router.route("/refresh-token").post(refreshAccessToken)

router.route("/change-password").post(upload.none(),verifyJWT,changeCurrentPassword)

router.route("/current-user").get(verifyJWT,getCurrentUser)

router.route("/update-details").patch(verifyJWT,upload.none(),updateAccountDetails)

router.route("/update-avatar").patch(
    verifyJWT,upload.single("avatar"),
    updateUserAvatar)

router.route("/update-cover").patch(
    verifyJWT,upload.single("coverImage"),
    updateUserCover)

router.route("/user-profile/:username").get(
    verifyJWT,getUserCurrentProfile)

router.route("/watch-history").get(
    verifyJWT,getWatchHistory)

export default router;