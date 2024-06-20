Java.perform(function() {

    var image_interception_class = Java.use('X.EAY');
    console.log("CONNECTED");

    
    image_interception_class.$init.overload('android.graphics.Bitmap').implementation = function(bitmap){
        console.log("IN INIT");
       
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
        console.log(bs);
      


        // Run the actual code
        this.$init(bitmap);

    };
             

});