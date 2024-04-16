import mongoose, { Schema as Schema, model } from 'mongoose';

const RecipeSchema = new Schema({
    name: { type: String, required: true },
    description: { type: String, required: false },
    ingredients: [{
        ingredient: { type: mongoose.Schema.Types.ObjectId, ref: 'Ingredient' },
        quantity: { type: Number, required: false },
        quantityType: { type: String, required: false },
        remark: { type: String, required: false },
    }],
    createdDate: { type: Date, default: Date.now }
});


const Recipe = mongoose.model('Recipe', RecipeSchema);

export { Recipe };