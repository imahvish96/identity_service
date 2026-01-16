import fs from "fs";
import path from "path";

export function loadTemplate(name: string, variables: Record<string, string>) {
    let html = fs.readFileSync(
        path.join(__dirname, `../templates/${name}.html`),
        "utf8"
    );

    for (const key in variables) {
        html = html.replace(`{{${key}}}`, variables[key]);
    }

    return html;
}