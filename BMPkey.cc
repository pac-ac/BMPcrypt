#include <iostream>
#include <SDL2/SDL.h>
#include "misc/input.h"
#include "misc/prng.h"

int main(int argc, const char* argv[]) {

	if (argc < 4) {
	
		std::cerr << "Must execute with output file name and dimensions.\n";
		std::cerr << "e.g. './BMPkey image.bmp 315 267'\n";
		return 0;
	}	

        constexpr int WIN_MULTIPLY = 1;
        constexpr int RGB_VAL = 256;

        //int size_w, size_l;

        uint16_t extraIter;

        uint64_t seedNum, seedNumR, seedNumG, seedNumB;
        uint16_t countNum, countNumR, countNumG, countNumB;

        const unsigned int WIDTH = std::stoi(argv[2]);
        const unsigned int LENGTH = std::stoi(argv[3]);

        //number of extra pixels to generate
        extraIter = iterNumIn();

        //starting conditions that decide how the key is generated
        seedNum = seedIn("point");
        countNum = iterateIn();

        seedNumR = seedIn("red");
        countNumR = iterateIn();

        seedNumG = seedIn("green");
        countNumG = iterateIn();

        seedNumB = seedIn("blue");
        countNumB = iterateIn();

        uint64_t RNG_mod1 = randGen(seedNum, countNum);
        uint64_t RNG_mod2 = randGen(RNG_mod1, countNum);

        uint64_t RNG_red = randGen(seedNumR, countNumR);
        uint64_t RNG_green = randGen(seedNumG, countNumG) + WIDTH;
        uint64_t RNG_blue = randGen(seedNumB, countNumB) + LENGTH;
  
	const char *bmpFile = argv[1];

        //initialize SDL window
        SDL_Window *window = nullptr;
        SDL_Renderer *renderer = nullptr;

        SDL_Init(SDL_INIT_EVERYTHING);

        SDL_CreateWindowAndRenderer(WIDTH*WIN_MULTIPLY, LENGTH*WIN_MULTIPLY, 0, &window, &renderer);
        SDL_RenderSetScale(renderer, WIN_MULTIPLY, WIN_MULTIPLY);

        SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
        SDL_RenderClear(renderer);
        SDL_Delay(10);

	//make window black on init
	SDL_RenderFillRect(renderer, NULL); 
        SDL_RenderPresent(renderer);
       	
	std::cout << "\nSuccessfully initialized SDL window." << '\n';


        int point1 = 0;
        int point2 = 0;

	
        for (int w = 0; w < WIDTH; w++) {

                //SDL_RenderClear(renderer);
                point1 = w;
                std::cout << "Generating column " << (w + 1) << " out of " << WIDTH << "..." << '\r';

                for (int l = 0; l < LENGTH; l++) {

                        point2 = l;

                        RNG_red =   randGen(RNG_green, countNumB ^ l);
                        RNG_green = randGen(RNG_blue, countNumR | l);
                        RNG_blue =  randGen(RNG_red, countNumG + l);

                        //generate RGB values
                        SDL_SetRenderDrawColor(renderer,
                                        RNG_red % RGB_VAL,
                                        RNG_green % RGB_VAL,
                                        RNG_blue % RGB_VAL, 255);

                        //update backbuffer
                        SDL_RenderDrawPoint(renderer, w, l);
                        SDL_Delay(0.1);                                                                                                           
                }
        }

        point1 = RNG_mod1;
        point2 = RNG_mod2;

        for (int i = 0; i < extraIter; i++) {

                RNG_mod1 =  randGen(RNG_mod2, countNum + i);
                RNG_mod2 =  randGen(RNG_mod1, countNum - i);

		RNG_red =   randGen(RNG_green, countNumB ^ i);
		RNG_green = randGen(RNG_blue, countNumR | i);
		RNG_blue =  randGen(RNG_red, countNumG + i);

                point1 = randGen(RNG_mod1, (RNG_mod2 % RGB_VAL) + 1) % WIDTH;
                point2 = randGen(RNG_mod2, (RNG_mod1 % RGB_VAL) + 1) % LENGTH;

                //generate RGB values
                SDL_SetRenderDrawColor(renderer,
                                RNG_red % RGB_VAL,
                                RNG_green % RGB_VAL,
                                RNG_blue % RGB_VAL, 255);

                //update backbuffer
                SDL_RenderDrawPoint(renderer, point1, point2);
                SDL_Delay(0.1);
        }

        //render final image
        SDL_RenderPresent(renderer);

        //save SDL surface to BMP image.
        SDL_Surface *windowSurface = nullptr;
        SDL_Surface *saveSurface = nullptr;

        windowSurface = SDL_GetWindowSurface(window);

        //get surface data
        unsigned char *pixels = new(std::nothrow)
                unsigned char[windowSurface->w * windowSurface->h
                * windowSurface->format->BytesPerPixel];

        SDL_RenderReadPixels(renderer, NULL, 0,  pixels, windowSurface->w
                        * windowSurface->format->BytesPerPixel);

        saveSurface = SDL_CreateRGBSurfaceFrom(pixels, windowSurface->w, windowSurface->h,
                        windowSurface->format->BitsPerPixel, windowSurface->w *
                        windowSurface->format->BytesPerPixel, windowSurface->format->Rmask,
                        windowSurface->format->Gmask, windowSurface->format->Bmask,
                        windowSurface->format->Amask);

        //save file to disk     
        if (SDL_SaveBMP(saveSurface, bmpFile) != 0) {

                std::cout << "\n\nFailed to save file to disk." << '\n';
                std::cout << '\t' << SDL_GetError() << '\n' << '\n';

                SDL_FreeSurface(saveSurface);
                saveSurface = nullptr;

                delete[] pixels;

                SDL_FreeSurface(windowSurface);
                windowSurface = nullptr;

                return 1;
        }

        //free memory
        SDL_FreeSurface(saveSurface);

        saveSurface = nullptr;
        delete[] pixels;

        SDL_FreeSurface(windowSurface);
        windowSurface = nullptr;

        std::cout << "\n\nSuccessfully generated and saved image." << '\n';
        SDL_Delay(3000);

        std::cout << "\nExiting..." << '\n';
        return 0;
}
