import express from 'express'
const router = express.Router();

import { getAllIngredients, getIngredient, createIngredient, updateIngredient, deleteIngredient } from '../controllers/ingredients.js'

router.route('/').get(getAllIngredients).post(createIngredient);
router.route('/:id').get(getIngredient).patch(updateIngredient).delete(deleteIngredient);

export { router as ingredientsRouter };