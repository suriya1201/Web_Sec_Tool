import os
import asyncio
from typing import Optional

import openai
import anthropic
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

class AISummaryClient:
    def __init__(self) -> None:
        """
        Initialize AI clients with API keys from environment variables.
        Prioritizes Gemini, then falls back to OpenAI and Anthropic.
        """
        # --- Gemini Setup ---
        self.gemini_available = False
        gemini_api_key = os.getenv("GEMINI_API_KEY")
        if gemini_api_key:
            try:
                genai.configure(api_key=gemini_api_key)
                self.gemini_model = genai.GenerativeModel('gemini-2.0-flash')
                self.gemini_available = True
            except Exception as e:
                print(f"Error setting up Gemini: {e}")

        # --- OpenAI Setup ---
        self.openai_available = False
        openai_api_key = os.getenv("OPENAI_API_KEY")
        if openai_api_key:
            try:
                self.openai_client = openai.OpenAI(api_key=openai_api_key)
                self.openai_default_model = "gpt-4o-mini"
                self.openai_available = True
            except Exception as e:
                print(f"Error setting up OpenAI: {e}")

        # --- Anthropic Setup ---
        self.anthropic_available = False
        anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
        if anthropic_api_key:
            try:
                self.anthropic_client = anthropic.Anthropic(api_key=anthropic_api_key)
                self.anthropic_default_model = "claude-3-sonnet-20240229"
                self.anthropic_available = True
            except Exception as e:
                print(f"Error setting up Anthropic: {e}")

    async def get_summary(self, scan_results: str, summary_prompt: str, model: Optional[str] = None) -> str:
        """
        Generate a summary of scan results using AI models.
        
        Args:
            scan_results: The raw scan results text to summarize
            summary_prompt: The prompt template for summarization
            model: (Optional) Force a specific model ("gemini", "openai", "anthropic")
            
        Returns:
            str: The generated summary. Returns empty string on failure.
        """
        try:
            if model == "openai" and self.openai_available:
                return await self._summarize_with_openai(scan_results, summary_prompt)
            elif model == "anthropic" and self.anthropic_available:
                return await self._summarize_with_anthropic(scan_results, summary_prompt)
            elif model == "gemini" and self.gemini_available:
                return await self._summarize_with_gemini(scan_results, summary_prompt)
            else:
                # Try models in order: Gemini -> OpenAI -> Anthropic
                if self.gemini_available:
                    try:
                        return await self._summarize_with_gemini(scan_results, summary_prompt)
                    except Exception as e:
                        print(f"Gemini summarization failed: {e}")
                
                if self.openai_available:
                    try:
                        return await self._summarize_with_openai(scan_results, summary_prompt)
                    except Exception as e:
                        print(f"OpenAI summarization failed: {e}")
                
                if self.anthropic_available:
                    try:
                        return await self._summarize_with_anthropic(scan_results, summary_prompt)
                    except Exception as e:
                        print(f"Anthropic summarization failed: {e}")
                
                raise ValueError("No AI models available or all failed to provide summaries")
        
        except Exception as e:
            print(f"Error in generating summary: {str(e)}")
            return ""

    async def _summarize_with_gemini(self, scan_results: str, summary_prompt: str) -> str:
        """Generate summary using Google Gemini."""
        formatted_prompt = summary_prompt.format(text=scan_results)
        response = self.gemini_model.generate_content(
            formatted_prompt,
            generation_config=genai.types.GenerationConfig(
                candidate_count=1,
                max_output_tokens=1500,
                temperature=0.1
            )
        )
        return response.candidates[0].content.parts[0].text.strip()

    async def _summarize_with_openai(self, scan_results: str, summary_prompt: str) -> str:
        """Generate summary using OpenAI."""
        formatted_prompt = summary_prompt.format(text=scan_results)
        response = self.openai_client.chat.completions.create(
            model=self.openai_default_model,
            messages=[
                {"role": "user", "content": formatted_prompt}
            ],
            max_tokens=1500,
            temperature=0.1
        )
        return response.choices[0].message.content.strip()

    async def _summarize_with_anthropic(self, scan_results: str, summary_prompt: str) -> str:
        """Generate summary using Anthropic Claude."""
        formatted_prompt = summary_prompt.format(text=scan_results)
        response = self.anthropic_client.messages.create(
            model=self.anthropic_default_model,
            max_tokens=1500,
            temperature=0.1,
            messages=[{"role": "user", "content": formatted_prompt}]
        )
        return response.content[0].text.strip()

# Helper function for synchronous calls from the existing code
def get_ai_summary(scan_results, summary_prompt, model=None):
    """Synchronous wrapper for the asynchronous get_summary method."""
    client = AISummaryClient()
    return asyncio.run(client.get_summary(scan_results, summary_prompt, model))