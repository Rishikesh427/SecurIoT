const minor = new Set(['a', 'an', 'and', 'as', 'at', 'but', 'by', 'for', 'in', 'of', 'on', 'or', 'the', 'to', 'with']);
export function titleCase(text: string): string {
  return text.split(/(\s+)/).map((word, index) => {
    if (/^\s+$/.test(word) || !word) return word;
    if (index > 0 && minor.has(word.toLowerCase())) return word.toLowerCase();
    return word[0].toUpperCase() + word.slice(1);
  }).join('');
}
