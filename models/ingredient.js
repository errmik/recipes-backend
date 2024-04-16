import mongoose, { Schema as Schema, model } from 'mongoose';

const IngredientSchema = new Schema({
    name: { type: String, required: true },
    alcoholic: { type: Boolean, default: false },
    description: {type: String, required: false},
    createdDate: { type: Date, default: Date.now }
});

const Ingredient = mongoose.model('Ingredient', IngredientSchema);

export { Ingredient };
