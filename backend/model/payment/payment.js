const mongoose = require('mongoose');

const PaymentSchema = new mongoose.Schema(
  {
    shop_name: {
      type: String,
      required: [true, 'Please add a shop name'],
    },
    user_id: {
      type: mongoose.Schema.Types.ObjectId,
      required: [true, 'Please add a user id'],
      ref: 'USER',
    },
    user_name: {
      type: String,
      required: [true, 'Please add a user name']
    },
    shop_id: {
      type: mongoose.Schema.Types.ObjectId,
      required: [true, 'Please add a shop id'],
    },
    //      ref: ['Booking',"Cart"],
    amount: {
      type: Number,
      required: true,
    },
    paymentDate: {
      type: Date,
      default: Date.now,
    },
    paymentStatus: {
      type: String,
      enum: ['paid', 'pending', 'failed'],
      default: 'pending',
    },
  },
  {
    timestamps: true,
  }
);

const PaymentModel = mongoose.model('Payment', PaymentSchema);

module.exports = PaymentModel;