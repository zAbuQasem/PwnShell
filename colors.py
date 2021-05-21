class ColorsSet:
	RED = '\033[31m'
	GREEN = '\033[38;5;82m'
	YELLOW = '\033[33m'
	BLUE = '\033[34m'
	MAGENTA = '\033[35m'
	CYAN = '\033[36m'
	WHITE = '\033[37m'
	RESET = '\033[0m'
class Colors:
	def __init__(self, default_color=None):
		if default_color:
			self.default_color = default_color
			print(default_color)
		else:
			self.default_color = None
	def set_default_color(self, default_color):
		self.default_color = default_color
	def get_colored_text(self, text, color):
		if self.default_color:
			return f'{color}{text}{ColorsSet.RESET}{self.default_color}'
		return f'{color}{text}{ColorsSet.RESET}'
