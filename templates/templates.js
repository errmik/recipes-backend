import { readFile } from 'fs/promises';
import Mustache from 'mustache';
import path from 'path';

const transformTemplate = async (filepath, data) => {

    var template = await readFile(filepath, 'utf8')

    return Mustache.render(template, data);

}

export { transformTemplate }

