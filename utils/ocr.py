import pytesseract
from PIL import Image


pytesseract.pytesseract.tesseract_cmd = (
    r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)


def extract_text_from_image(image):

    image = Image.open(image)

    image = image.convert("RGB")

    text = pytesseract.image_to_string(
        image,
        config="--psm 6"
    )

    return text