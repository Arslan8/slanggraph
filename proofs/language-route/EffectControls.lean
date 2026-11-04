import LanguageEffects
namespace LanguageEffects.Controls
open LanguageEffects

def reader : Code := (.seq (.seq .pure (.seq (.effect "read_text") .pure)) .pure)
example : check ["read_text"] reader = true := by decide
def two_reads : Code := (.seq (.seq (.seq .pure (.seq (.effect "read_text") .pure)) (.seq (.seq .pure (.seq (.effect "read_text") .pure)) .pure)) .pure)
example : check ["read_text"] two_reads = true := by decide
def select : Code := (.seq (.seq (.seq .pure (.seq .pure .pure)) (.choice (.seq (.seq .pure (.seq (.effect "read_text") .pure)) .pure) .pure)) (.seq .pure .pure))
example : check ["read_text"] select = true := by decide
def keyword : Code := (.seq .pure (.seq (.seq .pure (.seq (.effect "read_text") .pure)) .pure))
example : check ["read_text"] keyword = true := by decide
def while_reads : Code := (.seq .pure (.seq (.seq (.repeat (.seq (.seq .pure (.seq (.seq .pure .pure) .pure)) (.seq (.seq .pure (.seq (.effect "read_text") .pure)) (.seq (.seq .pure (.seq .pure .pure)) .pure)))) (.seq (.seq .pure (.seq (.seq .pure .pure) .pure)) .pure)) (.seq .pure .pure)))
example : check ["read_text"] while_reads = true := by decide
def for_reads : Code := (.seq .pure (.seq (.seq .pure .pure) (.seq (.seq .pure .pure) (.seq (.seq (.repeat (.seq (.seq .pure (.seq .pure (.seq .pure .pure))) (.seq .pure (.seq (.seq .pure (.seq .pure .pure)) (.seq (.seq .pure (.seq (.effect "read_text") .pure)) .pure))))) (.seq (.seq .pure (.seq .pure (.seq .pure .pure))) .pure)) (.seq .pure .pure)))))
example : check ["read_text"] for_reads = true := by decide
def string_loop : Code := (.seq (.seq .pure (.seq (.effect "read_text") .pure)) (.seq .pure (.seq .pure (.seq .pure (.seq .pure (.seq (.seq (.repeat (.seq (.seq .pure (.seq (.seq .pure .pure) .pure)) (.seq (.seq .pure (.seq .pure .pure)) (.seq (.seq .pure (.seq .pure .pure)) (.seq (.seq (.seq .pure (.seq .pure .pure)) (.choice (.seq (.seq .pure (.seq .pure .pure)) .pure) .pure)) .pure))))) (.seq (.seq .pure (.seq (.seq .pure .pure) .pure)) .pure)) (.seq (.seq .pure .pure) .pure)))))))
example : check ["read_text"] string_loop = true := by decide
def continue_break : Code := (.seq .pure (.seq .pure (.seq (.seq .pure .pure) (.seq (.seq (.repeat (.seq (.seq .pure (.seq .pure (.seq .pure .pure))) (.seq .pure (.seq (.seq .pure (.seq .pure .pure)) (.seq (.seq (.seq .pure (.seq .pure .pure)) (.choice (.seq .pure .pure) .pure)) (.seq (.seq .pure (.seq (.effect "read_text") .pure)) (.seq .pure .pure))))))) (.seq (.seq .pure (.seq .pure (.seq .pure .pure))) .pure)) (.seq .pure .pure)))))
example : check ["read_text"] continue_break = true := by decide
def infinite : Code := (.seq (.seq (.repeat (.seq .pure (.seq (.seq .pure (.seq (.effect "read_text") .pure)) .pure))) (.seq .pure .pure)) .pure)
example : check ["read_text"] infinite = true := by decide
def loop_escape : Code := (.seq (.seq (.repeat (.seq .pure (.seq (.seq (.effect "open") .pure) .pure))) (.seq .pure .pure)) .pure)
example : check ["read_text"] loop_escape = false := by decide
end LanguageEffects.Controls
