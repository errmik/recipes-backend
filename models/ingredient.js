import mongoose, { Schema as Schema, model } from 'mongoose';

const ingredientSchema = new Schema({
    name: { type: String, required: true },
    alcoholic: { type: Boolean, required: true },
    description: {type: String, required: false},
    createdDate: { type: Date, default: Date.now }
});

const Ingredient = mongoose.model('Ingredient', ingredientSchema);

export { Ingredient };
