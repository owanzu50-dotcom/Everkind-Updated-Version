const replacePlaceholders = (sql) => {
    let output = "";
    let parameterIndex = 1;
    let quote = null;

    for (let index = 0; index < sql.length; index += 1) {
        const character = sql[index];
        const nextCharacter = sql[index + 1];

        if (quote) {
            output += character;
            if (character === quote) {
                if (nextCharacter === quote) {
                    output += nextCharacter;
                    index += 1;
                } else {
                    quote = null;
                }
            }
            continue;
        }

        if (character === "'" || character === '"') {
            quote = character;
            output += character;
            continue;
        }

        if (character === "?") {
            output += `$${parameterIndex}`;
            parameterIndex += 1;
            continue;
        }

        output += character;
    }

    return output;
};

const translatePostgresSql = (sql) => {
    let translated = String(sql)
        .replace(/\bINSERT\s+OR\s+IGNORE\s+INTO\b/gi, "INSERT INTO")
        .replace(/\bGROUP_CONCAT\s*\(/gi, "STRING_AGG(")
        .replace(/\bdatetime\s*\(/gi, "public.datetime(")
        .replace(/\bdate\s*\(/gi, "public.date(")
        .replace(/(?<!")\bcarePlan\b(?!")/g, '"carePlan"')
        .replace(/(?<!")\bnextVisit\b(?!")/g, '"nextVisit"');

    const wasInsertOrIgnore = /\bINSERT\s+OR\s+IGNORE\s+INTO\b/i.test(sql);
    if (wasInsertOrIgnore && !/\bON\s+CONFLICT\b/i.test(translated)) {
        translated = `${translated.trim().replace(/;$/, "")} ON CONFLICT DO NOTHING`;
    }

    return replacePlaceholders(translated);
};

module.exports = {
    replacePlaceholders,
    translatePostgresSql,
};
