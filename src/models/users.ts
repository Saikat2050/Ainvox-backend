import mongoose from "mongoose"
import uniqueValidator from "mongoose-unique-validator"
const Schema = mongoose.Schema

const userSchema = new Schema(
	{
		name: {
			type: String,
			required: true
		},
		email: {
			type: String,
			required: true
		},
		roleId: {type: Number, required: true},
		mobile: {type: Number, required: false},
		password: {type: String, required: true},
		dob: {type: Date, required: false},
		address: {type: String, required: false},
		city: {type: String, required: false},
		state: {type: String, required: false},
		country: {type: String, required: false},
		postalCode: {type: String, required: false},
		secrectCode: {type: String, required: false},
		lastActivatedOn: {type: Date, required: false},
		isVerified: {type: Boolean, default: false},
		isActive: {type: Boolean, default: true},
		isDeleted: {type: Boolean, default: false}
	},
	{timestamps: true}
)
userSchema.plugin(uniqueValidator)

const User = mongoose.model("User", userSchema)
export default User
