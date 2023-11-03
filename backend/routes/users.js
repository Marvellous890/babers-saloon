const express = require("express")


const { protect } = require("../middleware/authmiddleware")
const { register_users, login_users,updateUser, getUser, getallusers } = require("../controller/users/users.controller")
const Router = express.Router()



//register users
Router.route("/register").post(register_users)
//login users 
Router.route("/login").post(login_users)
//update users
Router.route('/update/:userId').put(protect, updateUser)
//get one user
Router.route('/getone').get(protect,getUser)
//get all
Router.route('/getall').get(protect,getallusers)

module.exports=Router