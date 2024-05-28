import bchlib
import glob
from PIL import Image, ImageOps
import numpy as np
import tensorflow as tf
# zoe
#import tensorflow.contrib.image
import tensorflow_addons as tfa
from tensorflow.python.saved_model import tag_constants
from tensorflow.python.saved_model import signature_constants

# zoe
import hashlib
import random

BCH_POLYNOMIAL = 137
BCH_BITS = 5

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('model', type=str)
    parser.add_argument('--image', type=str, default=None)
    parser.add_argument('--images_dir', type=str, default=None)
    parser.add_argument('--secret_size', type=int, default=100)
    args = parser.parse_args()

    if args.image is not None:
        files_list = [args.image]
    elif args.images_dir is not None:
        files_list = glob.glob(args.images_dir + '/*')
    else:
        print('Missing input image')
        return

    sess = tf.compat.v1.InteractiveSession(graph=tf.Graph())

    model = tf.compat.v1.saved_model.loader.load(sess, [tag_constants.SERVING], args.model)

    input_image_name = model.signature_def[signature_constants.DEFAULT_SERVING_SIGNATURE_DEF_KEY].inputs['image'].name
    input_image = tf.compat.v1.get_default_graph().get_tensor_by_name(input_image_name)

    output_secret_name = model.signature_def[signature_constants.DEFAULT_SERVING_SIGNATURE_DEF_KEY].outputs['decoded'].name
    output_secret = tf.compat.v1.get_default_graph().get_tensor_by_name(output_secret_name)

    # zoe
    bch = bchlib.BCH(BCH_POLYNOMIAL, BCH_BITS)
    # bch = bchlib.BCH(BCH_BITS, BCH_POLYNOMIAL)

    for filename in files_list:
        print(f'filename:{filename}')
        image = Image.open(filename).convert("RGB")
        image = np.array(ImageOps.fit(image,(400, 400)),dtype=np.float32)
        image /= 255.

        print(f'image:{image.shape}')
        print(f'input_image:{input_image}')

        feed_dict = {input_image:[image]}
        #print(f'feed_dict:{feed_dict}')
 
        secret = sess.run([output_secret],feed_dict=feed_dict)[0][0]
        print(f'secret:{secret.shape}')

        packet_binary = "".join([str(int(bit)) for bit in secret[:96]])
        packet = bytes(int(packet_binary[i : i + 8], 2) for i in range(0, len(packet_binary), 8))
        print(f'packet:{packet}')
        packet = bytearray(packet)
        print(f'packet:{packet}')
        print(f'packet_binary:{packet_binary}')

        #packet = bytearray(b'Hello  \xc5\x10\xfb\xe2\xe0')
        #print(f'bch.ecc_bytes:{bch.ecc_bytes}')

        data, ecc = packet[:-bch.ecc_bytes], packet[-bch.ecc_bytes:]

        print(f'packet1:{packet}')
        print(f'data1:{data}')
        print(f'ecc1:{ecc}')
        
        
        # zoe
        #bitflips = bch.decode_inplace(data, ecc)
        max_data_len = bch.n // 8 - (bch.ecc_bits + 7) // 8

        print('max_data_len: %d' % (max_data_len,))
        print('ecc_bits: %d (ecc_bytes: %d)' % (bch.ecc_bits, bch.ecc_bytes))
        print('m: %d' % (bch.m,))
        print('n: %d (%d bytes)' % (bch.n, bch.n // 8))
        print('prim_poly: 0x%x' % (bch.prim_poly,))
        print('t: %d' % (bch.t,))

        sha1_corrupt = hashlib.sha1(packet)
        print('packet sha1: %s' % (sha1_corrupt.hexdigest(),))

        def bitflip(packet):
            byte_num = random.randint(0, len(packet) - 1)
            bit_num = random.randint(0, 7)
            packet[byte_num] ^= (1 << bit_num)

        # make BCH_BITS errors
        for _ in range(bch.t):
            bitflip(packet)

        bch.data_len = max_data_len
        print(f'bch:{bch}')
        print(f'max_data_len:{max_data_len}')
        print(f'data:{data}')
        print(f'ecc:{ecc}')

        bitflips = bch.decode(data, ecc)
        print(f'bitflips:{bitflips}')
        print('syn:', bch.syn)
        print('errloc:', bch.errloc)

        correct = bch.correct(data, ecc)
        print(f'correct:{correct}')

        
        if packet != -1:
            try:
                code = data.decode("utf-8")
                print(filename, code)
                continue
            except:
                continue
        print(filename, 'Failed to decode')


if __name__ == "__main__":
    main()