import frida
import time
import io
from PIL import Image



# The name of the target process
TARGET_PROCESS = 'instagram'

# JavaScript code to be injected
js_hook_code = """
Java.perform(function() {

    var image_interception_class = Java.use('X.EAY');

    
    image_interception_class.$init.overload('android.graphics.Bitmap').implementation = function(bitmap){
        
        var Bitmap = Java.use("android.graphics.Bitmap");
        var ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
        var CompressFormat = Java.use("android.graphics.Bitmap$CompressFormat");

        
        // Ensure args[0] is a Bitmap object
        var mp = Java.cast(bitmap, Bitmap);
    
        // Create ByteArrayOutputStream object
        var stream = ByteArrayOutputStream.$new();
    
        // Compress image
        mp.compress(CompressFormat.PNG.value, 100, stream);
        
        var bs = stream.toByteArray();
        // Log results
        send(bs);
      


        // Run the actual code
        this.$init(bitmap);

    };
             

});
"""

# Callback to handle messages from JavaScript code
def on_message(message, data):
    byte_array = message["payload"]
    
    # Convert the array of integers to bytes
    byte_data = bytes([b if b >= 0 else b + 256 for b in byte_array])

    # Create an image from the byte data
    image = Image.open(io.BytesIO(byte_data))

    # Save the image to a file
    image.save('./output.png')


def test_frida():    
    device = frida.get_usb_device()

    print(device)

    # pid = device.spawn([])
    session = device.attach(TARGET_PROCESS)
    
    print(session)

    # Inject JavaScript code
    script = session.create_script(js_hook_code)
    print(script)
    script.on('message', on_message)
    script.load()

    while True:
        time.sleep(1)


if __name__ == "__main__":
    test_frida()
    

