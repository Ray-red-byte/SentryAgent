import os
import google.generativeai as genai

class GeminiClient:
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            print("⚠️ Warning: GEMINI_API_KEY not found.")
            return

        genai.configure(api_key=self.api_key)
        
        # 1. Get all available models that support text generation
        print("🔍 Scanning for available Gemini models...")
        try:
            my_models = [m.name for m in genai.list_models() if 'generateContent' in m.supported_generation_methods]
            print(f"✅ Found models: {my_models}")
            
            # 2. Select the best match automatically
            # We prefer Flash (fast), then Pro (standard), then anything else.
            preferred_order = [
                'models/gemini-1.5-flash',
                'models/gemini-1.5-flash-001',
                'models/gemini-1.5-pro',
                'models/gemini-pro',
                'models/gemini-1.0-pro'
            ]
            
            selected_model = None
            for pref in preferred_order:
                if pref in my_models:
                    selected_model = pref
                    break
            
            # If none of our preferences exist, just take the first valid one we found
            if not selected_model and my_models:
                selected_model = my_models[0]
            
            if not selected_model:
                raise ValueError("No generative models found for this API key.")

            print(f"🤖 Auto-selected model: {selected_model}")
            self.model = genai.GenerativeModel(selected_model)

        except Exception as e:
            print(f"⚠️ Error listing models: {e}")
            # Fallback hardcoded just in case
            self.model = genai.GenerativeModel('models/gemini-pro')

    def analyze(self, prompt: str):
        if not self.api_key:
            return "❌ Error: API Key missing."
            
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Error contacting Gemini: {e}"
        
    def analyze_with_cache(self, prompt: str, cache_name: str):
        """
        Connects to an existing cache to answer the prompt.
        """
        if not self.api_key:
            return "❌ Error: API Key missing."

        try:
            # 1. Reconnect to the specific cache
            cache = genai.caching.CachedContent.get(cache_name)
            
            # 2. Initialize model pointing to that cache
            # CRITICAL: This must be the exact same model version used to create the cache
            model = genai.GenerativeModel.from_cached_content(cached_content=cache)
            
            # 3. Generate
            print(f"⚡ Querying Cache {cache_name}...")
            response = model.generate_content(prompt)
            return response.text
            
        except Exception as e:
            print(f"🔥 Cache Error: {e}")
            # Fallback: If cache fails (expired?), try standard analyze
            return self.analyze(prompt)