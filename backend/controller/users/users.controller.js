const asynchandler = require("express-async-handler");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const USER = require("../../model/users/user");
const SHOPS = require("../../model/shops/shop");
const COMMENT = require("../../model/blogs/comments");
const BLOGS = require("../../model/blogs/blog");
const logger = require("../../utils/logger");
const { DateTime } = require("luxon");
const { convertToWAT } = require("../../utils/datetime");

const currentDateTimeWAT = DateTime.now().setZone("Africa/Lagos");

const cookieOptions = {
  sameSite: "none",
  secure: true,
  // domain: ".example.com"
};

//
//desc login users
//access private-depending on endpoint needs
//routes /users/login
const login_users = asynchandler(async (req, res) => {
  const { email, password } = req.body;
  const clientIp = req.clientIp;

  if (!email || !password) return res.status(400).send("fields can not be empty");

  const user = await USER.findOne({ email });
  // console.log(user);

  if (!user) {
    return res.status(404).send("User does not exist");
  }

  if (await bcrypt.compare(password, user.password)) {
    // Successful login

    const referredUsers = await USER.find(
      { referredBy: user.referCode },
      "firstName lastName userName pictureUrl"
    );

    const referralCount = referredUsers.length;
    const token = generateToken(user._id);
    const userWithoutPassword = await USER.findById(user.id).select(
      "-password"
    );

    // send user object and token
    res.json({ ...userWithoutPassword._doc, token, referralCount, });
  } else {
    res.status(400).send("Invalid credentials",);
  }
});

//desc register users
//access public
//router /users/register
const register_users = asynchandler(async (req, res) => {
  const {
    firstName,
    lastName,
    email,
    password,
    userName,
    phoneNumber,
    referralCode,
  } = req.body;

  if (
    !firstName ||
    !lastName ||
    !email ||
    !password ||
    !userName ||
    !phoneNumber
  ) {
    return res.status(400).send("fields cannot be empty");
  }

  const findemail = await USER.findOne({ email: email });
  if (findemail) {
    return res.status(403).send("A user with this email already exists");
  }

  const exist = await USER.findOne({ userName: userName });
  if (exist) return res.status(403).send("User name already exist");

  if (referralCode) {
    const re = await USER.find({ referCode: referralCode });
    if (re) return res.status(403).send("invalid coupon");
  }

  const salt = await bcrypt.genSalt(10);
  const hashedpassword = await bcrypt.hash(password, salt);

  const createUsers = await USER.create({
    firstName,
    lastName,
    email,
    password: hashedpassword,
    userName,
    phoneNumber,
    referredBy: referralCode, // Add the referral code to the model
  });

  const codeone = createUsers._id.toString().slice(3, 7);
  const codetwo = firstName.toString().slice(0, 3);
  const codethree = firstName.toString().slice(0, 2);
  const codefour = userName.toString().slice(0, 2);
  const referrCode = `REF-${codeone}${codetwo}${codethree}${codefour}${codetwo}`;

  const updatereferral = await USER.findByIdAndUpdate(
    createUsers._id,
    { $set: { referCode: referrCode } },
    { new: true }
  );

  const token = generateToken(createUsers._id);

  // send user object via cookie
  res.json({ ...updatereferral._doc, token });
});

//access  private
//route /users/landing_page
//desc landing user page
const landing_page = asynchandler(async (req, res) => {
  try {
    const { id } = req.auth;

    const user = await USER.findById(id);
    if (!user)
      throw Object.assign(new Error("User not found"), { statusCode: 404 });
    const shops = await SHOPS.find({ approved: true });

    // Define the order of subscription types
    const subscriptionOrder = ["platinum", "gold", "basic"];

    // Sort shops based on subscription type and creation date
    shops.sort((a, b) => {
      const aIndex = subscriptionOrder.indexOf(a.subscriptionType);
      const bIndex = subscriptionOrder.indexOf(b.subscriptionType);

      if (aIndex !== bIndex) {
        return aIndex - bIndex;
      }

      // If the subscription type is the same, sort by creation date
      return b.createdAt - a.createdAt;
    });

    const blogs = await BLOGS.find({ approved: true });

    let blogDict = {};
    for (const blog of blogs) {
      const commentCount = await COMMENT.countDocuments({ blog_id: blog._id });
      blog.commentCount = commentCount;
      blogDict[blog] = commentCount;
    }

    const sortedShops = shops.map((shop) => ({ ...shop._doc, type: "shop" }));
    const sortedBlogs = Object.keys(blogDict).map((blog) => ({
      ...blog,
      type: "blog",
    }));

    const combinedData = [...sortedShops, ...sortedBlogs];

    combinedData.sort((a, b) => b.createdAt - a.createdAt);

    res.status(200).json({
      data: combinedData,
    });

    logger.info(
      `Landing page data fetched - ${res.statusCode} - ${res.statusMessage} - ${req.originalUrl} - ${req.method} - ${req.ip} - from ${req.ip}`
    );
  } catch (error) {
    console.error(error);
    throw Object.assign(new Error(`${error}`), { statusCode: error.statusCode });
    ;
  }
});

//access  public
//route /users/landing_page
//desc landing user page
const landingpage = asynchandler(async (req, res) => {
  try {
    const shops = await SHOPS.find({ approved: true });

    // Define the order of subscription types
    const subscriptionOrder = ["platinum", "gold", "basic"];

    // Sort shops based on subscription type and creation date
    shops.sort((a, b) => {
      const aIndex = subscriptionOrder.indexOf(a.subscriptionType);
      const bIndex = subscriptionOrder.indexOf(b.subscriptionType);

      if (aIndex !== bIndex) {
        return aIndex - bIndex;
      }

      // If the subscription type is the same, sort by creation date
      return b.createdAt - a.createdAt;
    });

    const blogs = await BLOGS.find({ approved: true });

    let blogDict = {};
    for (const blog of blogs) {
      const commentCount = await COMMENT.countDocuments({ blog_id: blog._id });
      blog.commentCount = commentCount;
      blogDict[blog] = commentCount;
    }

    const sortedShops = shops.map((shop) => ({ ...shop._doc, type: "shop" }));
    const sortedBlogs = Object.keys(blogDict).map((blog) => ({
      ...blog,
      type: "blog",
    }));

    const combinedData = [...sortedShops, ...sortedBlogs];

    combinedData.sort((a, b) => b.createdAt - a.createdAt);

    res.status(200).json({
      data: combinedData,
    });

    logger.info(
      `Landing page data fetched - ${res.statusCode} - ${res.statusMessage} - ${req.originalUrl} - ${req.method} - ${req.ip} - from ${req.ip}`
    );
  } catch (error) {
    console.error(error);
    throw Object.assign(new Error(`${error}`), { statusCode: error.statusCode });
  }
});

//get one user
//access private for user
const getUser = asynchandler(async (req, res) => {
  try {
    const { id } = req.auth;
    const { user_id } = req.body;
    let owner = false;
    const user = await USER.findById(user_id);
    if (id === user._id || process.env.role === "superadmin") {
      owner = true;
      if (!user) {
        throw Object.assign(new Error("user Not authorized"), {
          statusCode: 404,
        });
      }

      const referredUsers = await USER.find(
        { referredBy: user.referCode },
        "firstName lastName userName pictureUrl"
      );
      const referralCount = referredUsers.length;
      const token = generateToken(id);
      res.status(202).header("Authorization", `Bearer ${token}`).json({
        status: 200,
        user: user,
        referralCount: referralCount,
        referredUsers: referredUsers,
      });

      logger.info(
        `User with id ${userId} information was fetched successfully. Referred users count: ${referralCount}`
      );
    } else {
      throw new Error("unauthorized");
    }
  } catch (error) {
    throw Object.assign(new Error(`${error}`), { statusCode: error.statusCode });
  }
});
//desc get all users for admin
//access private for admins only
//access private
// desc list all shops
// route /shops/al
const getallusers = asynchandler(async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const pageSize = parseInt(req.query.pageSize) || 10;
  console.log(page, "   ", pageSize);
  const { id } = req.auth;
  const user = await USER.findById(id);
  try {
    if (user.role === "superadmin" || process.env.role === "superadmin") {
      const allUsers = await USER.find()
        .skip((page - 1) * pageSize)
        .limit(pageSize);
      const referredUsers = await USER.aggregate([
        {
          $group: {
            _id: "$referredBy",
            count: { $sum: 1 },
          },
        },
      ]);

      const usersWithReferrals = allUsers.map((user) => {
        const referral = referredUsers.find((u) => u._id === user.referCode);
        return {
          ...user._doc,
          referralCount: referral ? referral.count : 0,
        };
      });

      const totalCount = await USER.countDocuments();

      const token = generateToken(id);
      res
        .status(200)
        .header("Authorization", `Bearer ${token}`)
        .json({
          data: usersWithReferrals,
          page: page,
          totalPages: Math.ceil(totalCount / pageSize),
        });

      logger.info(
        `users were fetched- ${res.statusCode} - ${res.statusMessage} - ${req.originalUrl} - ${req.method} - ${req.ip} - from ${req.ip}`
      );
    } else {
      throw Object.assign(new Error("Not authorized"), { statusCode: 403 });
    }
  } catch (error) {
    console.log(error);
    throw Object.assign(new Error(`${error}`), { statusCode: error.statusCode });
  }
});

// Controller function to update a user
//route /user/updateac
//access private
//data updateData
const updateUser = asynchandler(async (req, res) => {
  const { userId } = req.params;
  const clientIp = req.clientIp;
  const { id } = req.auth;
  const updateData = req.body;

  try {
    if (!userId || !updateData) {
      throw Object.assign(new Error("Fields cannot be empty"), { statusCode: 400 });
      ;
    }

    const updatUser = await USER.findById(userId);
    console.log(updatUser._id);
    if (
      !(userId === updatUser._id.toString()) ||
      !(process.env.role === "superadmin")
    ) {
      throw Object.assign(new Error("Not authorized"), { statusCode: 403 });
    }

    // Check if a file was uploaded
    if (req.body.data) {
      // Upload file to Cloudinary
      const result = await cloudinary.uploader.upload(req.body.data, { resource_type: 'image', format: 'png' });
      // Add the Cloudinary URL of the uploaded image to the update data
      updateData.profile_image = result.secure_url;
    }

    const updatedUser = await USER.findByIdAndUpdate(userId, updateData, {
      new: true, // Return the updated user document
    });

    if (!updatedUser) {
      throw Object.assign(new Error("User not  found"), { statusCode: 404 });
    }

    const token = generateToken(id);
    res
      .status(200)
      .header("Authorization", `Bearer ${token}`)
      .json(updatedUser);
    const createdAt = updatedUser.updatedAt; // Assuming createdAt is a Date object in your Mongoose schema
    const watCreatedAt = convertToWAT(createdAt);
    const location = getLocation(clientIp);
    logger.info(
      `user with id ${userId},updated profile ${watCreatedAt} - ${res.statusCode} - ${res.statusMessage} - ${req.originalUrl} - ${req.method} - ${req.ip}  - from ${req.ip}`
    );
  } catch (error) {
    console.error(error);
    throw Object.assign(new Error(`${error}`), { statusCode: error.statusCode });
  }
});
const getLocation = asynchandler(async (ip) => {
  try {
    // Set endpoint and your access key
    const accessKey = process.env.ip_secret_key;
    const url =
      "http://apiip.net/api/check?ip=" + ip + "&accessKey=" + accessKey;

    // Make a request and store the response
    const response = await fetch(url);

    // Decode JSON response:
    const result = await response.json();

    // Output the "code" value inside "currency" object
    return response.data;
  } catch (error) {
    console.log(error);
    return null;
  }
});
//update subscription
//access private
const forum_status = asynchandler(async (req, res) => {
  try {
    const { id } = req.auth;
    const { userId } = req.params;
    const { status } = req.body;
    const role = await USER.findById(id);
    if (
      role._role === "superadmin" ||
      !(process.env.role.toString() === "superadmin")
    )
      throw new Error("not authorized");
    const updatedUser = await USER.findByIdAndUpdate(
      userId,
      { $set: { banned_from_forum: status } },
      { new: true }
    );
    if (!updatedUser) {
      throw Object.assign(new Error("error updating"), { statusCode: 400 });
    }

    const token = generateToken(id);
    res.status(200).header("Authorization", `Bearer ${token}`).json({
      successful: true,
    });
    logger.info(
      `admin with id ${id}, changed user with ${userId} forum status - ${res.statusCode} - ${res.statusMessage} - ${req.originalUrl} - ${req.method} - ${req.ip} - from ${req.ip} `
    );
  } catch (error) {
    throw Object.assign(new Error(`${error}`), { statusCode: error.statusCode });
  }
});

const generateToken = (id) => {
  return jwt.sign(
    {
      id,
    },
    process.env.JWT_SECRET,
    { expiresIn: "12h" }
  );
};
const searchItems = asynchandler(async (req, res) => {
  const query = req.query.query;
  try {
    const shopResults = await SHOPS.find({ $text: { $search: query } });
    const blogResults = await BLOGS.find({ $text: { $search: query } });

    // Combine and sort the results
    const combinedResults = [...shopResults, ...blogResults].sort(
      (a, b) => b.createdAt - a.createdAt
    );

    // const token = generateToken(id);.header("Authorization", `Bearer ${token}`)
    res.status(200).json({
      data: combinedResults,
    });

    logger.info(
      `Search results fetched - ${res.statusCode} - ${res.statusMessage} - ${req.originalUrl} - ${req.method} - ${req.ip} - from ${req.ip}`
    );
  } catch (error) {
    console.error(error);
    throw Object.assign(new Error(`${error}`), { statusCode: error.statusCode });
    ;
  }
});

const uploadImg = asynchandler(async (req, res) => {
  const fs = require('fs');
  const path = require('path');

  // Function to decode and save Data URL to a file
  const saveDataURLToFile = (dataURL) => {
    const matches = dataURL.match(/^data:(.+);base64,(.+)$/);
    if (!matches || matches.length !== 3) {
      throw new Error('Invalid data URL format');
    }

    const [, mimeType, imageData] = matches;
    const fileExtension = mimeType.split('/')[1];
    const randomName = `${Date.now()}-${Math.round(Math.random() * 1E9)}.${fileExtension}`;
    const filePath = path.join(__dirname, 'public/product-images', randomName);

    fs.writeFileSync(filePath, Buffer.from(imageData, 'base64'));

    return randomName;
  };

  const { image } = req.body;

  if (!image) {
    return res.status(400).send('No image data found.');
  }

  try {
    const fileName = saveDataURLToFile(image);
    res.send(fileName);
  } catch (error) {
    res.status(500).send('Failed to save the image.');
  }
});

module.exports = {
  register_users,
  login_users,
  landing_page,
  updateUser,
  getUser,
  getallusers,
  forum_status,
  searchItems,
  landingpage,
};