from Dex import Dex
import sys 


data = []

def getcode(dexpath , dexout):
    dex = Dex(dexpath)
    dex.print_dex_header()


def main():
    if (len(sys.argv)) != 3 :
        print("usage : xxxx dexfile output")
    dexpath = sys.argv[1]
    dexout = sys.argv[2]
    getcode(dexpath,dexout)

if __name__ == '__main__':
    main() 