import frida
import time

from PIL import Image
from smqtk_classifier import ClassifyImage
from tqdm import tqdm

import numpy as np


MODEL_CACHED = False

# The name of the target process
TARGET_PROCESS = 'instagram'

current_img = None

# JavaScript code to be injected
js_hook_code = """
Java.perform(function() {
    var Bitmap = Java.use("android.graphics.Bitmap");
    var BitmapFactory = Java.use("android.graphics.BitmapFactory");
    var ByteArrayInputStream = Java.use("java.io.ByteArrayInputStream");
    var ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");


    var thread_class = Java.use('X.80q');

    var cached_ml_object = null;

    thread_class.invokeSuspend.implementation = function(k33){
         //Get return of the invoke suspend function.
         
         //Checks to see if the current instance is the ML case.
         if(this.A03.value == 5){
                
            cached_ml_object = this.A02.value;
            send("MODEL CACHED");
            
        }

        var ret = this.invokeSuspend(k33);

        return ret;

    }
             

    // Expose a function to be called from Python
    rpc.exports = {
        callpostmessage: function(pixelMatrix) {
            var width = pixelMatrix.length;
            var height = pixelMatrix[0].length; 

            // Access the Bitmap.Config class
            var BitmapConfig = Java.use('android.graphics.Bitmap$Config');

            // Get the ARGB_8888 enum value
            var argb8888Config = BitmapConfig.ARGB_8888.value;

            // Example: Creating a Bitmap using ARGB_8888 config
            var Bitmap = Java.use('android.graphics.Bitmap');
            var bitmap = Bitmap.createBitmap(width, height, argb8888Config);

            // Convert the pixel matrix to a 1D array of ARGB values
            var pixels = [];
            for (var i = 0; i < width; i++) {
                for (var j = 0; j < height; j++) {
                    var pixel = pixelMatrix[i][j];
                    var red = (pixel[0] & 0xFF) << 16;
                    var green = (pixel[1] & 0xFF) << 8;
                    var blue = (pixel[2] & 0xFF);
                    var alpha = 0xFF << 24; // Assuming full opacity
                    var argb = alpha | red | green | blue;
                    pixels.push(argb);
                }
            }

            // Set the pixels on the bitmap
            bitmap.setPixels(pixels, 0, width, 0, 0, width, height);


            if(cached_ml_object == null){
                send("ML model not cached. Execute the model first to continue using this code.");
            }else{

                var clips_xray_obj = Java.cast(cached_ml_object,Java.use("com.instagram.ml.clipsxray.ClipsXRayVisualFeatureExtractor"))
                    

                var thing_7QR = Java.cast(clips_xray_obj.A01.value, Java.use("X.7QR"));

                
                var thing_7OB = Java.use("X.EAY").$new(bitmap);

                var list_thing = Java.use("java.util.Collections").singletonList(thing_7OB);
            
                var thing_G7o =  Java.use("X.7QR").A00(thing_7QR,list_thing);
                

                var list_thing2 = Java.cast(thing_G7o,Java.use("X.EAj")).A00.value;
                
                var ret_string = "";
                for(var k=0; k < list_thing2.size();k++){
                    var thing_7x6 = Java.cast(list_thing2.get(k),Java.use("X.8Lc"));
                    ret_string+= `${thing_7x6.A01.value},${thing_7x6.A00.value} \t`;
                }
                send(ret_string);
            }


        }
    };
});
"""

class frida_model (ClassifyImage):
    """ Blackbox model for Instagram's actual model on the phone. """
    
    def __init__(self):
        device = frida.get_usb_device()

        # pid = device.spawn([])
        session = device.attach(TARGET_PROCESS)
        # Inject JavaScript code
        script = session.create_script(js_hook_code)
        script.on('message', on_message)
        script.load()

        print("Script loaded")

        self.script = script

        self.labels_set = False
        self.sal_class_labels={}
        self.t_labels= ['fire', 'grass', 'sunglass', 'cueball', 'germanshepherd', 'spaghetti', 'redhorse', 'blowing_candle', 'triumphal_arch', 'firearm', 'rabbit', 'sink', 'firework', 'chessboard', 'glove', 'church', 'lavabo', 'violin', 'chute', 'pyramid', 'ferocactus', 'rock', 'columbalivia', 'trampolining', 'diningroom', 'huron', 'skating', 'video_game', 'racing_vehicles', 'manicotti', 'beard', 'horseradish', 'dessert', 'wall_painting', 'flan', 'oystershells', 'park', 'belladonnalily', 'great_wall_of_china', 'drink', 'overpass', 'road', 'elephant', 'phone', 'pier', 'anthurium', 'frenchfries', 'fireengine', 'teamaker', 'parade', 'workout', 'woodwind', 'camel', 'washing_dishes', 'camping', 'bib', 'karate', 'wedding', 'khimar', 'carving', 'basketball_jersey', 'daylily', 'sheath', 'baseball', 'bong', 'skydiving', 'banana', 'falls', 'people', 'watermelon', 'wheelhorse', 'sewing', 'opening_champagne', 'bus', 'cablecar', 'chimborazo', 'confectionery', 'weddingcake', 'steak', 'face', 'paintedturtle', 'meat', 'onion', 'giraffe', 'trumpet', 'winter', 'cymbal', 'businesssuit', 'coast', 'bathroom', 'reading', 'food', 'helicopter', 'bagel', 'laundromat', 'chocolate', 'tiramisu', 'samoyede', 'playing', 'has_text', 'shuffleboard', 'llama', 'ball', 'gamefowl', 'footwear', 'bubble', 'fog', 'living_room', 'dieffenbachia', 'suntea', 'taj_mahal', 'nib', 'flatware', 'bowling', 'otterhound', 'custardapple', 'newsroom', 'drum', 'tenderloin', 'coconutwater', 'trail', 'audi', 'lepidoptera', 'denim', 'watertable', 'sleepwear', 'skislope', 'anvil', 'digitalwatch', 'garage', 'car', 'railroad', 'statue', 'washington_monument', 'accordion', 'hiking', 'eiffel_tower', 'vanda', 'gimbal', 'poundcake', 'nighttime', 'playroom', 'crustacean', 'siamesecats', 'wheel_chair', 'icelolly', 'outdoor', 'lacrosse', 'dinner', 'rift', 'legoset', 'monkeybread', 'corn', 'pagoda', 'doll', 'tree', 'guitar', 'boating', 'snackfood', 'conservatory', 'shackle', 'illustration', 'instrument', 'police_car', 'eyeglasses', 'bbq_barbecue', 'sports_field', 'staircase', 'tapiocapudding', 'knife', 'cornerpocket', 'scallop', 'brick_wall', 'chihuahua', 'cornusmas', 'lake', 'broomstick', 'sydney_opera_house', 'snaredrum', 'blond', 'sansevieria', 'laptop', 'abacus', 'pinesnake', 'platerack', 'entrecote', 'balloon', 'tarotcards', 'potato', 'mountararat', 'crablegs', 'christmas', 'adenium', 'candy', 'ropebridge', 'curtain', 'eating', 'pinball', 'granite', 'goose', 'manholecover', 'crochet', 'acrylic', 'climbing_wall', 'cup', 'fireplug', 'picnic', 'obverse', 'mezcal', 'reticulatedpythons', 'soundboard', 'darts', 'horse', 'bridge', 'leather', 'water', 'bellagio_fountains', 'soccer', 'water_skiing', 'pokerchips', 'anchovy', 'rearviewmirror', 'farmland', 'pennant', 'bicycle', 'snow_mountain', 'hollyhock', 'autumn_fall', 'driving', 'grill', 'crucifix', 'river', 'cockatoo', 'chocolatebar', 'windmill', 'lagomorph', 'dalmatian', 'bellis', 'copperplate', 'diving', 'scrambler', 'clothesline', 'backpack', 'puzzle', 'birthday_cake', 'swimming', 'cheeseburger', 'cirrocumulus', 'skyscraper', 'wadingbirds', 'pool', 'stub', 'study', 'clockface', 'weight_lifting', 'swine', 'giantpanda', 'egyptiancat', 'shorts', 'freight', 'suitcase', 'mowing', 'bananatree', 'sucklingpig', 'ananas', 'dog', 'cat', 'brunswickstew', 'jewelry', 'amanita', 'softball', 'cavia', 'grandfatherclock', 'hot_air_balloon', 'apple', 'mt_rushmore', 'interior_design', 'pinballmachine', 'watchstrap', 'ovis', 'train', 'tamp', 'crotalus', 'weimaraner', 'sprinkler', 'paeonia', 'passeriformes', 'funeral', 'rainbowlorikeet', 'cornsnake', 'hallway', 'fishing', 'tillandsia', 'fungi', 'silvia', 'poodledogs', 'fineart', 'sofa', 'concert', 'indoor', 'smoking', 'snake', 'bakken', 'art_painting', 'table', 'tomato', 'hair', 'ocean', 'hair_long', 'castle', 'barber', 'activewear', 'nymphalidae', 'stew', 'rugelach', 'pallette', 'money', 'dress', 'golden_gate_bridge', 'sky', 'tabbouleh', 'watch', 'stadium', 'arctic', 'snowing', 'casino', 'tram', 'rollingstock', 'statue_of_liberty', 'aviation', 'galleria', 'glass', 'spearpoint', 'parrot', 'begoniarex', 'beefburger', 'chicken', 'whale', 'peachorchard', 'paragliding', 'brownie', 'christmas_tree', 'bird', 'plant', 'animation', 'menorah', 'ferris_wheel', 'tempura', 'swan', 'ursus', 'skiing', 'rabbithutch', 'wildsheep', 'fishpond', 'slot', 'drawing', 'etamin', 'dumpling', 'crowd', 'cheerleading', 'gym', 'hockey', 'floorplan', 'boxing', 'book', 'tortilla', 'flange', 'graduation', 'bottle', 'sundae', 'bonsai', 'shrimp', 'football', 'pythonidae', 'biking', 'mountain', 'pull_ups', 'eyewear', 'animal', 'tatting', 'badminton', 'windbell', 'standardschnauzer', 'toy', 'boa', 'nopal', 'christmascake', 'sextant', 'table_tennis', 'subwaytrains', 'floodlight', 'tv', 'beach', 'bed', 'rooibos', 'monkey', 'suiting', 'street', 'keyring', 'surfing', 'combine', 'jigsawpuzzle', 'cuttingboard', 'computer', 'cupcake', 'coffee', 'steeple', 'tent', 'stingingnettles', 'scope', 'ambulance', 'squirrel', 'shoes', 'bedroom', 'bottleneck', 'fruit', 'mountainbike', 'cloche', 'pool', 'fish', 'pet', 'wildfowl', 'beanie', 'pizza', 'popart', 'horizon', 'americanfoxhound', 'peacock', 'ice_hockey', 'child', 'baby', 'chair', 'hardcandy', 'torte', 'iceskate', 'birdnests', 'boletusedulis', 'echinocereus', 'gymnastics', 'basketball', 'motherboard', 'longan', 'flower', 'playingcard', 'glaze', 'bubblegum', 'hookah', 'perfume', 'towelrack', 'tamale', 'belljar', 'beefsteak', 'painting', 'linocut', 'saxophone', 'wallclocks', 'dais', 'aeonium', 'hearth', 'equestrian', 'volleyball', 'kitchen', 'poker', 'orangepeel', 'braiding', 'wrecking', 'lace', 'motorcycle', 'wave', 'silverfish', 'condiment', 'brass', 'turtle', 'cockerel', 'amphibian', 'blue', 'redcurrant', 'roti', 'piano', 'broccoli', 'flute', 'cake', 'playing_music', 'red', 'rhino', 'riding_scooter', 'pie', 'bactriancamel', 'popcorn', 'wine', 'churchhats', 'blonde', 'bay', 'dartboard', 'drag', 'spotteddick', 'zoo', 'colocasia', 'dancing', 'cloud', 'DoF', 'blurry', 'motionBlur', 'light', 'colVivid', 'balanceElements', 'colHarmony', 'aesthetics_rating', 'RoT', 'violence', 'nudity']
        self.old_image = ""
    
    def get_labels(self):
        
        return self.t_labels
        
    
    def parse_message_string(self,string):
        elements = string.split("\t")
        labels = []
        probs = []

        for i,ele in enumerate(elements):
            if not "," in ele:
                continue
            label,prob = ele.strip().split(",")
            labels.append(label)
            probs.append(float(prob))
            self.sal_class_labels[i] = label
        
    
        return probs 

    def set_labels(self,labels):
        self.t_labels = labels
    
    def classify_images(self, image_iter):
        # Input may either be an NDaray, or some arbitrary iterable of NDarray images.
        global current_image
        for img in tqdm(image_iter):
            execute_model(img,self.script)            

            while self.old_image == current_image:
                time.sleep(0.01)

            self.old_image = current_image
            output = self.parse_message_string(current_image)

            yield dict(zip(self.t_labels, output))

    def predict(self, img):
        # Input may either be an NDaray, or some arbitrary iterable of NDarray images.
        global current_image

        execute_model(img,self.script)            

        while not current_image:
            time.sleep(0.23)

        output = self.parse_message_string(current_image)
        current_image = None
        
        return output,self.t_labels
    
    def get_config(self):
        # Required by a parent class.
        return {}

current_image = ""

# Callback to handle messages from JavaScript code
def on_message(message, data):
    global MODEL_CACHED
    global current_image
    print("Got message")
    if message["payload"] == "MODEL CACHED":
        MODEL_CACHED = True
        print("CACHED MODEL")
    if MODEL_CACHED:
        current_image = message["payload"]
        # print(current_image)
    

def load_image_as_matrix(image_path):
    """Load an image from the given path into a matrix (numpy array)."""
    try:
        with Image.open(image_path) as img:
            return np.array(img)
    except Exception as e:
        print(f"Error loading image {image_path}: {e}")
        return None


def execute_model(mat,script):    

    # Convert the numpy array to a list of lists for sending to the Frida script
    pixel_matrix_list = mat.tolist()

    
    while not MODEL_CACHED:
        time.sleep(1)
    
    script.exports.callpostmessage(pixel_matrix_list)
    


def test_frida():    
    device = frida.get_usb_device()

    # pid = device.spawn([])
    session = device.attach(TARGET_PROCESS)

    # Inject JavaScript code
    script = session.create_script(js_hook_code)
    script.on('message', on_message)
    script.load()

    test_image = "../datasets/fairface-img-margin025-trainval/train/1.jpg"
    mat = load_image_as_matrix(test_image)


    # Convert the numpy array to a list of lists for sending to the Frida script
    pixel_matrix_list = mat.tolist()

    while True:
        time.sleep(1)
        script.exports.callpostmessage(pixel_matrix_list)
        


if __name__ == "__main__":
    test_frida()