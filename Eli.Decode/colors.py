import re

class TextRenderer (object) :
    def __init__ (self, colors={}) :
        self.colors = colors
        self.r = re.compile("({{[^{}]+}})")
    def _split (self, spec) :
        try :
            spec = self.colors.get(spec, spec)
            if "+" in spec :
                color, st = spec.split("+", 1)
            else :
                color, st = spec, None
            color = self.colors.get(color, color)
            if ":" in color :
                fg, bg = (int(x) % 16 for x in color.split(":"))
            else :
                fg, bg = int(color) % 16, 0
        except :
            fg, bg, st = 0, 0, None
        return fg, bg, st
    def _sub (self, match) :
        return ""
    def __call__ (self, text) :
        return self.r.sub(self._sub, text)

class AnsiRenderer (TextRenderer) :
    fg = ["39"] + ["38;5;%s" % i for i in range(1, 16)]
    bg = ["49"] + ["48;5;%s" % i for i in range(1, 16)]
    st = {"DEFAULT" : "0", "BOLD" : "1", "ITALICS" : "3", "UNDERLINE" : "4",
          "STRIKEOUT" : "9"}
    def _sub (self, match) :
        fg, bg, st = self._split(match.group(0)[2:-2].strip())
        st = self.st.get(st, None)
        if st is None :
            return "\x1b[%s;%sm" % (self.fg[fg], self.bg[bg])
        else :
            return "\x1b[%s;%s;%sm" % (self.fg[fg], self.bg[bg], st)
    def __call__ (self, text) :
        return TextRenderer.__call__(self, text) + "\x1b[0m"

class HtmlRenderer (TextRenderer) :
    fg = ["#FFF", "#000", "#F00", "#0F0", "#00F", "#0FF", "#F0F", "#FF0", "#800",
          "#080", "#008", "#088", "#808", "#880", "#888", "#C0C0C0"]
    bg = ["#000", "#FFF", "#F00", "#0F0", "#00F", "#0FF", "#F0F", "#FF0", "#800",
          "#080", "#008", "#088", "#808", "#880", "#888", "#C0C0C0"]
    st = {}
    def __init__ (self, colors={}) :
        TextRenderer.__init__(self, colors)
        self.nested = False
    def _sub (self, match) :
        fg, bg, st = self._split(match.group(0)[2:-2].strip())
        st = self.st.get(st, None)
        if self.nested :
            if st is None :
                return ("</span><span style='color:%s; background-color:%s'>"
                        % (self.fg[fg], self.bg[bg]))
            else :
                return ("</span><span style='color:%s; background-color:%s; %s'>"
                        % (self.fg[fg], self.bg[bg], st))
        else :
            self.nested = True
            if st is None :
                return ("<span style='color:%s; background-color:%s'>"
                        % (self.fg[fg], self.bg[bg]))
            else :
                return ("<span style='color:%s; background-color:%s; %s'>"
                        % (self.fg[fg], self.bg[bg], st))
    def __call__ (self, text) :
        self.nested = False
        ret = TextRenderer.__call__(self, text)
        if self.nested :
            ret += "</span>"
        return ret
