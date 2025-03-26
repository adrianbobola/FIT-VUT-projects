/*!
 * @file
 * @brief This file contains implementation of gpu
 *
 * @author Tomáš Milet, imilet@fit.vutbr.cz
 */

#include <student/gpu.hpp>

uint32_t cislovanie_vrcholov(VertexArray const& vao, uint32_t cislo_vrchola) {
	//pointer=null - indexovanie vypnute
	if (vao.indexBuffer == NULL) {
		return cislo_vrchola;
	}
	// indexovanie vrcholov zapnute
	else {
		// 8-bit indexovanie
		if (vao.indexType == IndexType::UINT8) {
			uint8_t* index = (uint8_t*)vao.indexBuffer;
			return index[cislo_vrchola];
		}
		// 16-bit indexovanie
		if (vao.indexType == IndexType::UINT16) {
			uint16_t* index = (uint16_t*)vao.indexBuffer;
			return index[cislo_vrchola];
		}
		// 32-bit indexovanie
		if (vao.indexType == IndexType::UINT32) {
			uint32_t* index = (uint32_t*)vao.indexBuffer;
			return index[cislo_vrchola];
		}
	}
}

//! [drawTrianglesImpl]
void drawTrianglesImpl(GPUContext& ctx, uint32_t nofVertices) {
	for (uint32_t vrcholy = 0; vrcholy < nofVertices; vrcholy++)
	{
		InVertex vertex_shader_input;
		OutVertex vertex_shader_output;
		vertex_shader_input.gl_VertexID = cislovanie_vrcholov(ctx.vao, vrcholy);

		for (int i = 0; i < maxAttributes; i++) {
			// citacia hlava povolena
			if (ctx.vao.vertexAttrib->type != AttributeType::EMPTY) {
				uint64_t offset = ctx.vao.vertexAttrib->offset;
				uint64_t stride = ctx.vao.vertexAttrib->stride;
				uint32_t gl_vertex_ID = vertex_shader_input.gl_VertexID;

				// kopirujem atributy typu float
				if (ctx.vao.vertexAttrib->type == AttributeType::FLOAT) {
					vertex_shader_input.attributes->v1 = (vertex_shader_input.attributes[i].v1 + (float) offset/4 + ((stride * gl_vertex_ID) / 4) - 1);
				}
				// kopirujem atributy typu vec2
				if (ctx.vao.vertexAttrib->type == AttributeType::VEC2) {
					vertex_shader_input.attributes->v2 = (vertex_shader_input.attributes[i].v2 + glm::vec2(offset / 4 + ((stride * gl_vertex_ID) / 4) - 1));
				}
				// kopirujem atributy typu vec3
				if (ctx.vao.vertexAttrib->type == AttributeType::VEC3) {
					vertex_shader_input.attributes->v3 = (vertex_shader_input.attributes[i].v3 + glm::vec3(offset / 4 + ((stride * gl_vertex_ID) / 4) - 1));
				}
				// kopirujem atributy typu vec4
				if (ctx.vao.vertexAttrib->type == AttributeType::VEC4) {
					vertex_shader_input.attributes->v4 = (vertex_shader_input.attributes[i].v4 + glm::vec4(offset / 4 + ((stride * gl_vertex_ID) / 4) - 1));
				}
			}
		}
		ctx.prg.vertexShader(vertex_shader_output, vertex_shader_input, ctx.prg.uniforms);
	}
	/// \todo Tato funkce vykreslí trojúhelníky podle daného nastavení.<br>
	/// ctx obsahuje aktuální stav grafické karty.
	/// Parametr "nofVertices" obsahuje počet vrcholů, který by se měl vykreslit (3 pro jeden trojúhelník).<br>
	/// Bližší informace jsou uvedeny na hlavní stránce dokumentace.
}
//! [drawTrianglesImpl]

/**
 * @brief This function reads color from texture.
 *
 * @param texture texture
 * @param uv uv coordinates
 *
 * @return color 4 floats
 */
glm::vec4 read_texture(Texture const& texture, glm::vec2 uv) {
	if (!texture.data)return glm::vec4(0.f);
	auto uv1 = glm::fract(uv);
	auto uv2 = uv1 * glm::vec2(texture.width - 1, texture.height - 1) + 0.5f;
	auto pix = glm::uvec2(uv2);
	//auto t   = glm::fract(uv2);
	glm::vec4 color = glm::vec4(0.f, 0.f, 0.f, 1.f);
	for (uint32_t c = 0; c < texture.channels; ++c)
		color[c] = texture.data[(pix.y * texture.width + pix.x) * texture.channels + c] / 255.f;
	return color;
}

/**
 * @brief This function clears framebuffer.
 *
 * @param ctx GPUContext
 * @param r red channel
 * @param g green channel
 * @param b blue channel
 * @param a alpha channel
 */
void clear(GPUContext& ctx, float r, float g, float b, float a) {
	auto& frame = ctx.frame;
	auto const nofPixels = frame.width * frame.height;
	for (size_t i = 0; i < nofPixels; ++i) {
		frame.depth[i] = 10e10f;
		frame.color[i * 4 + 0] = static_cast<uint8_t>(glm::min(r * 255.f, 255.f));
		frame.color[i * 4 + 1] = static_cast<uint8_t>(glm::min(g * 255.f, 255.f));
		frame.color[i * 4 + 2] = static_cast<uint8_t>(glm::min(b * 255.f, 255.f));
		frame.color[i * 4 + 3] = static_cast<uint8_t>(glm::min(a * 255.f, 255.f));
	}
}

