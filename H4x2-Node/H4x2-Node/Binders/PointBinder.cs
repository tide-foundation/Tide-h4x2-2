// 
// Tide Protocol - Infrastructure for a TRUE Zero-Trust paradigm
// Copyright (C) 2022 Tide Foundation Ltd
// 
// This program is free software and is subject to the terms of 
// the Tide Community Open Code License as published by the 
// Tide Foundation Limited. You may modify it and redistribute 
// it in accordance with and subject to the terms of that License.
// This program is distributed WITHOUT WARRANTY of any kind, 
// including without any implied warranty of MERCHANTABILITY or 
// FITNESS FOR A PARTICULAR PURPOSE.
// See the Tide Community Open Code License for more details.
// You should have received a copy of the Tide Community Open 
// Code License along with this program.
// If not, see https://tide.org/licenses_tcoc2-0-0-en
//


using Microsoft.AspNetCore.Mvc.ModelBinding;
using H4x2_TinySDK.Ed25519;
using H4x2_Node.Helpers;

namespace H4x2_Node.Binders
{
    public class PointBinder : IModelBinder
    {
        public Task BindModelAsync(ModelBindingContext bindingContext)
        {
            if (bindingContext == null)
            {
                throw new ArgumentNullException(nameof(bindingContext));
            }

            var modelName = bindingContext.ModelName;

            // Try to fetch the value of the argument by name
            var valueProviderResult = bindingContext.ValueProvider.GetValue(modelName);

            if (valueProviderResult == ValueProviderResult.None || string.IsNullOrWhiteSpace(valueProviderResult.FirstValue))
            {
                return Task.CompletedTask;
            }

            if (!EncodedPointHelper.TryFromBase64String(valueProviderResult.FirstValue, out byte[] buffer))
            {
                bindingContext.ModelState.TryAddModelError(modelName, $"Is not a valid base64 string.");
                return Task.CompletedTask;
            }

            var model = Point.FromBytes(buffer);
            if (!model.IsSafePoint())
            {
                bindingContext.ModelState.TryAddModelError(modelName, $"Is not a valid point.");
                return Task.CompletedTask;
            }

            bindingContext.Result = ModelBindingResult.Success(model);
            return Task.CompletedTask;
        }
    }
}
