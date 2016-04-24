import sys, platform, traceback, time
import colors

_sys = platform.system()
if _sys in ("Linux", "Darwin") :
    colorize = colors.AnsiRenderer({
        "RED" :     "1:0",
        "GREEN" :   "2:0",
        "YELLOW" :  "3:0",
        "BLUE" :    "4:0",
        "MAGENTA" : "5:0",
        "CYAN" :    "6:0",
        "GRAY" :    "8:0",
        "CLEAR" :   "0:0+DEFAULT",
        "ERROR" :   "11:1+BOLD",
        "CHAPTER" : "0:0+UNDERLINE",
        "BOLD" :    "0:0+BOLD",
        "INPUT" :   "8:15",
		"TITLE":    "8:0+BOLD"})
else :
    colorize = colors.TextRenderer()

def error (text, banner="") :
    if not banner :
        banner = "error"
    sys.stderr.write(colorize("{{ERROR}}%s:{{CLEAR}} %s\n" % (banner, text.strip())))
    sys.stderr.flush()

def bug (prog=None, header=None) :
    err, val, tb = sys.exc_info()
    if prog :
        prog += " "
    else :
        prog = ""
    if header is None :
        header = ("{{ERROR}}%sbug found:{{RED}} please"
                  " send information below to"
                  " the developpers\n" % prog)
    else :
        header = header.strip() + "\n"
    sys.stderr.write(colorize(header))
    traceback.print_exception(err, val, tb, file=sys.stderr)
    sys.stderr.flush()

def out (*text) :
    sys.stdout.write(colorize(" ".join(text).rstrip() + "\n"))

def raw (*text) :
    sys.stdout.write(colorize(" ".join(text)))

def web (info=None, query=None, resp=None, error=None, debug=None, flash=None) :
    head = "{{GRAY}}[%s]{{CLEAR}}" % time.strftime("%H:%M:%S")
    lines = []
    if flash :
        lines.append("%s {{MAGENTA}}%s{{CLEAR}}" % (head, flash))
        head = " " * 10
    if info :
        lines.append("%s {{YELLOW}}%s{{CLEAR}}" % (head, info))
        head = " " * 10
    if query :
        lines.append("%s {{BLUE}}%s{{CLEAR}}" % (head, query))
        head = " " * 10
    if resp :
        if resp.startswith("4") :
            color = "RED"
        else :
            color = "GREEN"
        lines.append("%s {{GRAY}}=> {{%s}}%s{{CLEAR}}" % (head, color, resp))
        head = " " * 10
    if error :
        lines.append("%s {{RED}}%s{{CLEAR}}" % (head, error))
        head = " " * 10
    if debug :
        lines.append("%s {{GRAY}}%s{{CLEAR}}" % (head, debug))
    out("\n".join(lines))
